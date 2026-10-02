"""Content-free Contact finish observations from the actual frozen Core/Graph.

This is an observation of a durable B1 fence, not an execution journal event.
Only the installed recovery port calls capture while holding its authenticated
Core transaction and verified business snapshot. Archive DTOs never authorize
ordinary Contact execution or sending.
"""
from dataclasses import asdict, dataclass, fields
from contextlib import contextmanager, closing
from contextvars import ContextVar
import hashlib
import json
from pathlib import Path
import sqlite3
from weakref import WeakValueDictionary

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable

TABLE = 'authority_c09_contact_finish_originals_v1'
COLUMNS = ('namespace', 'operation_id', 'business_operation_id', 'original_json', 'original_digest')
DDL = (f'CREATE TABLE {TABLE}(namespace TEXT NOT NULL,operation_id TEXT NOT NULL,'
       'business_operation_id TEXT NOT NULL,original_json TEXT NOT NULL,original_digest TEXT NOT NULL,'
       'PRIMARY KEY(namespace,operation_id,business_operation_id))')
_ISSUED = WeakValueDictionary()
_PORTS = WeakValueDictionary()
_ACTIVE = ContextVar('installed_c09_contact_finish_scope_v1', default=None)


@dataclass(frozen=True)
class _ContactFinishScopeV1:
    port: object
    control: object
    seal: object
    verifier: str
    originals: tuple
    business_path: Path
    core_path: Path
    pointer_version: int
    manifest_digest: str
    quiescence_digest: str


def _issue_contact_finish_scope_v1(port, originals):
    from .c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4, ConnectionC09RecoveryOriginalsV4
    if (type(port) not in {InstalledC09RecoveryOriginalsV4, ConnectionC09RecoveryOriginalsV4}
            or _PORTS.get(id(port)) is not port or port._snapshot is None):
        raise AuthorityUnavailable('C09 Contact scope needs active exact installed freeze')
    seal, _old, _rows, verifier, business, core_db = port._snapshot
    if not business.in_transaction or not core_db.in_transaction:
        raise AuthorityUnavailable('C09 Contact scope snapshots closed')
    control = port._contact_control
    context = control.read_verified_current_storage_v1(verify_files=False)
    intent = control.read_operation_event_v1(seal.operation_id, 'INTENT')
    if context.stage != 'INTENT' or context.pointer_version != intent['pointer_version']:
        raise AuthorityUnavailable('C09 Contact scope is outside real INTENT')
    business_path = Path(business.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
    core_path = Path(core_db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True)
    selected = {m['role']: Path(m['resolved_path']).resolve(strict=True) for m in context.manifest['members']}
    if (business_path, core_path) != (selected['graph'], selected['core']):
        raise AuthorityUnavailable('C09 Contact scope selected files differ')
    scope = _ContactFinishScopeV1(port, control, seal, verifier, tuple(originals), business_path, core_path,
        context.pointer_version, context.manifest_digest, intent['details']['quiescence_original']['quiescence_digest'])
    _ISSUED[id(scope)] = scope
    return scope


def _register_contact_finish_port_v1(port):
    """Called at the end of the real, fully validated port constructors."""
    _PORTS[id(port)] = port


@contextmanager
def _contact_finish_graph_scope_v1(scope):
    if scope is None:
        yield
        return
    if _ISSUED.get(id(scope)) is not scope or scope.port._contact_finish_scope is not scope:
        raise AuthorityUnavailable('C09 Contact scope was not issued by actual installed freeze')
    token = _ACTIVE.set(scope)
    try:
        yield
    finally:
        _ACTIVE.reset(token)
        _ISSUED.pop(id(scope), None)
        if scope.port._contact_finish_scope is scope:
            scope.port._contact_finish_scope = None


def _revoke_contact_finish_scope_v1(port):
    scope = getattr(port, '_contact_finish_scope', None)
    if scope is not None:
        _ISSUED.pop(id(scope), None)
        port._contact_finish_scope = None


@contextmanager
def _scope_core_snapshot_v1(scope):
    from .c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4, ConnectionC09RecoveryOriginalsV4
    if type(scope.port) is InstalledC09RecoveryOriginalsV4:
        # The real Core lock/transaction sees committed WAL as well as main DB.
        # Never use immutable=1 on a running Core connection.
        with scope.port.core._tx() as db:
            yield db
    elif type(scope.port) is ConnectionC09RecoveryOriginalsV4:
        db = scope.port._connection_material[0]
        if not db.in_transaction:
            raise AuthorityUnavailable('C09 Contact cold Core snapshot is not pinned')
        yield db
    else:
        raise AuthorityUnavailable('C09 Contact Core issuer differs')


def require_contact_finish_graph_erasure_v1(db, *, namespace, operation_id, proof):
    """Actual immutable candidate connection, original scope and archived joins."""
    # The finite archive/inventory implementation is reviewable, but legacy
    # V4 cannot prove an absent Contact inventory after physical erasure. Its
    # versioned compatibility contract awaits the parent architecture decision.
    raise AuthorityUnavailable('C09 Contact complete versioned finish inventory unresolved; HOLD')


def _require_contact_finish_graph_erasure_closed_v1(db, *, namespace, operation_id, proof):
    """Proposed closed join; not an enabled erasure entry point."""
    scope = _ACTIVE.get()
    if (scope is None or _ISSUED.get(id(scope)) is not scope
            or scope.port._contact_finish_scope is not scope or not db.in_transaction):
        raise AuthorityUnavailable('C09 Contact authenticated finish context absent; HOLD')
    if Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True) != scope.business_path:
        raise AuthorityUnavailable('C09 Contact candidate is not the issued business source')
    context = scope.control.read_verified_current_storage_v1(verify_files=False)
    intent = scope.control.read_operation_event_v1(scope.seal.operation_id, 'INTENT')
    if (context.stage, context.pointer_version, context.manifest_digest,
            intent['details']['quiescence_original']['quiescence_digest']) != (
            'INTENT', scope.pointer_version, scope.manifest_digest, scope.quiescence_digest):
        raise AuthorityUnavailable('C09 Contact issued source or writer quiescence changed')
    matches = tuple(o for o in scope.originals if o.business_operation_id == operation_id)
    if len(matches) != 1:
        raise AuthorityUnavailable('C09 Contact finish operation absent; HOLD')
    original = matches[0]
    with _scope_core_snapshot_v1(scope) as core_db:
        if Path(core_db.execute('PRAGMA database_list').fetchone()[2]).resolve(strict=True) != scope.core_path:
            raise AuthorityUnavailable('C09 Contact actual Core source changed')
        saved = read_contact_finish_originals_v1(core_db, namespace=original.namespace, operation_id=original.operation_id)
        if original not in saved:
            raise AuthorityUnavailable('C09 Contact actual immutable archive changed')
        from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked, read_execution_recovery_facts_pin_v4_locked
        facts = read_execution_recovery_facts_v4_locked(core_db, scope.seal.namespace, operation_id=scope.seal.operation_id)
        pin = read_execution_recovery_facts_pin_v4_locked(core_db, scope.seal.namespace, operation_id=scope.seal.operation_id)
        if (facts is None or pin is None or pin.seal_digest != scope.seal.seal_digest
                or pin.facts_digest != facts.facts_digest or pin.verifier_commitment != scope.verifier
                or tuple(f for f in facts.graph_facts if f.operation_id == operation_id) != (contact_graph_fact_v1(original),)):
            raise AuthorityUnavailable('C09 Contact finish not bound to real frozen facts/pin')
        if original.operation_id != scope.seal.operation_id:
            if _read_authenticated_archived_contact_v1(core_db, control=scope.control,
                    namespace=original.namespace, business_operation_id=operation_id) != original:
                raise AuthorityUnavailable('C09 Contact prior consumed original changed')
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    actual = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if (actual is None or actual['original_digest'] != original.business_original_digest
            or canonical_digest(namespace) != original.business_namespace_digest
            or canonical_digest(actual['receipt']) != original.business_receipt_digest
            or canonical_serialize(actual['payload']['provenance']) != canonical_serialize(proof)
            or proof['qualification_digest'] != original.qualification_digest
            or tuple(sorted((canonical_digest(m['ref']), m['revision'], m['digest']) for m in proof['write_commitments'])) != original.write_commitments):
        raise AuthorityUnavailable('C09 Contact actual business COMMIT differs from finished observation')
    return original


def _hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


@dataclass(frozen=True, slots=True)
class C09ContactFinishOriginalV1:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    business_operation_id: str
    business_namespace_digest: str
    owner_attempt_id: str
    owner_request_digest: str
    permit_digest: str
    permit_subject_digest: str
    permit_holder_digest: str
    permit_token_digest: str
    generation: int
    fence_epoch: int
    fence_revision: int
    pinned_anchor: RestoreAnchor
    observed_core_anchor: RestoreAnchor
    finish_request_id: str
    finish_request_digest: str
    fence_row_commitment: str
    business_original_digest: str
    business_receipt_digest: str
    graph_receipt_commitment: str
    graph_write_set_commitment: str
    unresolved_obligation_commitment: str | None
    qualification_digest: str
    qualification_evidence_digest: str
    write_commitments: tuple[tuple[str, int, str], ...]
    observed_journal_id: str
    observed_execution_seq: int
    observed_execution_digest: str
    source_seal_digest: str
    verifier_commitment: str
    original_digest: str
    schema: str = 'sylanne3.c09.contact-finish-original.v1'

    def __post_init__(self):
        for name in ('authority_id', 'installation_id', 'namespace', 'operation_id',
                     'business_operation_id', 'owner_attempt_id', 'finish_request_id', 'observed_journal_id'):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise AuthorityUnavailable('C09 Contact finish identity absent')
        if (self.schema != 'sylanne3.c09.contact-finish-original.v1'
                or type(self.pinned_anchor) is not RestoreAnchor
                or type(self.observed_core_anchor) is not RestoreAnchor
                or (self.pinned_anchor.authority_id, self.pinned_anchor.namespace, self.pinned_anchor.activation_generation)
                != (self.authority_id, self.namespace, self.generation)
                or (self.observed_core_anchor.authority_id, self.observed_core_anchor.namespace)
                != (self.authority_id, self.namespace)
                or self.observed_core_anchor.activation_generation < self.generation
                or self.finish_request_id != 'finish:' + self.owner_attempt_id):
            raise AuthorityUnavailable('C09 Contact finish typed scope differs')
        for name, minimum in (('generation', 1), ('fence_epoch', 1), ('fence_revision', 0), ('observed_execution_seq', 0)):
            if type(getattr(self, name)) is not int or getattr(self, name) < minimum:
                raise AuthorityUnavailable('C09 Contact finish integer identity differs')
        for name in ('business_namespace_digest', 'owner_request_digest', 'permit_digest',
                     'permit_subject_digest', 'permit_holder_digest', 'permit_token_digest',
                     'fence_row_commitment', 'business_original_digest', 'business_receipt_digest',
                     'graph_receipt_commitment', 'graph_write_set_commitment', 'qualification_digest',
                     'qualification_evidence_digest', 'source_seal_digest', 'verifier_commitment', 'original_digest'):
            if not _hash(getattr(self, name)):
                raise AuthorityUnavailable('C09 Contact finish canonical commitment differs')
        if (not self.finish_request_digest.startswith('sha256:')
                or not _hash(self.finish_request_digest[7:])
                or self.observed_execution_seq == 0 and self.observed_execution_digest != 'genesis'
                or self.observed_execution_seq > 0 and not _hash(self.observed_execution_digest.removeprefix('sha256:'))
                or self.unresolved_obligation_commitment is not None and not _hash(self.unresolved_obligation_commitment)):
            raise AuthorityUnavailable('C09 Contact finish observation head differs')
        if (type(self.write_commitments) is not tuple or not 1 <= len(self.write_commitments) <= 1024
                or self.write_commitments != tuple(sorted(set(self.write_commitments)))
                or any(type(row) is not tuple or len(row) != 3 or not _hash(row[0])
                       or type(row[1]) is not int or row[1] < 1 or not _hash(row[2]) for row in self.write_commitments)):
            raise AuthorityUnavailable('C09 Contact finish finite write inventory differs')
        if canonical_digest(tuple(getattr(self, f.name) for f in fields(self) if f.name != 'original_digest')) != self.original_digest:
            raise AuthorityUnavailable('C09 Contact finish original digest differs')


def contact_finish_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(C09ContactFinishOriginalV1)}:
        raise AuthorityUnavailable('C09 Contact finish closed wire differs')
    body = dict(raw)
    body['pinned_anchor'] = RestoreAnchor(**body['pinned_anchor'])
    body['observed_core_anchor'] = RestoreAnchor(**body['observed_core_anchor'])
    body['write_commitments'] = tuple(tuple(row) for row in body['write_commitments'])
    return C09ContactFinishOriginalV1(**body)


def install_contact_finish_archive_v1(db):
    if not db.in_transaction:
        raise AuthorityUnavailable('C09 Contact archive needs real Core transaction')
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if row is None:
        db.execute(DDL)
    elif row != (DDL,):
        raise AuthorityUnavailable('C09 Contact archive schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = TABLE + '_no_' + action.lower()
        sql = f"CREATE TRIGGER {name} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'C09 Contact finish immutable'); END"
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None:
            db.execute(sql)
        elif row != (sql,):
            raise AuthorityUnavailable('C09 Contact archive immutable trigger differs')


def validate_contact_finish_row_v1(columns, row):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise AuthorityUnavailable('C09 Contact archive columns differ')
    original = contact_finish_original_from_wire_v1(json.loads(row[3]))
    if (row[:3] != (original.namespace, original.operation_id, original.business_operation_id)
            or row[4] != original.original_digest or row[3] != canonical_serialize(asdict(original))):
        raise AuthorityUnavailable('C09 Contact archive canonical row differs')
    return original


def read_contact_finish_originals_v1(db, *, namespace, operation_id):
    present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if present is None:
        return ()
    require_contact_finish_archive_schema_v1(db)
    columns = tuple(row[1] for row in db.execute(f'PRAGMA table_info({TABLE})'))
    return tuple(validate_contact_finish_row_v1(columns, row) for row in db.execute(
        f'SELECT * FROM {TABLE} WHERE namespace=? AND operation_id=? ORDER BY business_operation_id',
        (namespace, operation_id)))


def require_contact_finish_archive_schema_v1(db):
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() != (DDL,):
        raise AuthorityUnavailable('C09 Contact archive exact schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = TABLE + '_no_' + action.lower()
        sql = f"CREATE TRIGGER {name} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'C09 Contact finish immutable'); END"
        if db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone() != (sql,):
            raise AuthorityUnavailable('C09 Contact archive immutable schema differs')


def contact_graph_fact_v1(original):
    """Explicit compound v1; unrelated V4 single-event bytes remain unchanged."""
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
    return SanitizedGraphFactV4(original.business_operation_id,
        canonical_digest(('sylanne3.c09.contact-graph-finish.v1', original.graph_receipt_commitment, original.original_digest)),
        canonical_digest(('sylanne3.c09.contact-graph-writes.v1', original.graph_write_set_commitment, original.write_commitments)),
        original.unresolved_obligation_commitment)


INVENTORY_PREFIX = 'c09-contact-finish-inventory:'


def contact_finish_inventory_fact_v1(operation_id, originals):
    """Explicit finite archive inventory: missing-all is detectable on restore.

    This new reserved fact kind does not change any old single-event bytes.
    Its members are the complete typed archives issued in this source frame.
    """
    from ..runtime.c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
    members = tuple(sorted((o.business_operation_id, o.original_digest) for o in originals))
    if not members or len(members) > 1024 or len({m[0] for m in members}) != len(members):
        raise AuthorityUnavailable('C09 Contact finish archive inventory differs')
    return SanitizedGraphFactV4(INVENTORY_PREFIX + operation_id,
        canonical_digest(('sylanne3.c09.contact-finish-inventory.v1', operation_id, members)),
        canonical_digest(('sylanne3.c09.contact-finish-inventory-writes.v1', members)), None)


def validate_contact_finish_frame_inventory_v1(db, facts):
    originals = read_contact_finish_originals_v1(db, namespace=facts.namespace, operation_id=facts.operation_id)
    inventories = tuple(f for f in facts.graph_facts if f.operation_id.startswith(INVENTORY_PREFIX))
    expected = () if not originals else (contact_finish_inventory_fact_v1(facts.operation_id, originals),)
    if inventories != expected:
        raise AuthorityUnavailable('C09 Contact complete archived inventory absent or changed')
    return originals


def _read_authenticated_archived_contact_v1(db, *, control, namespace, business_operation_id):
    """Reauthenticate a consumed fence using actual selected Core and signed control.

    The current INTENT may use an earlier RELEASED frame. Neither an archive DTO
    nor a business state string supplies this authenticated control context.
    """
    from .c09_storage_control_v1 import InstalledC09StorageReaderV1
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_v4_locked, read_execution_recovery_facts_pin_v4_locked
    from .c09_recovery_resolver_v4 import read_recovery_bindings_v1_locked
    if not db.in_transaction or not isinstance(control, InstalledC09StorageReaderV1):
        raise AuthorityUnavailable('C09 Contact consumed finish needs installed control')
    context = control.read_verified_current_storage_v1(verify_files=False)
    selected = next(m for m in context.manifest['members'] if m['role'] == 'core')
    if Path(db.execute('PRAGMA database_list').fetchone()[2]).resolve() != Path(selected['resolved_path']).resolve():
        raise AuthorityUnavailable('C09 Contact consumed Core is not selected storage')
    with control._db() as protected:
        pointer = control._current(protected)
        if (pointer['pointer_version'], pointer['current_manifest_digest'], pointer['stage']) != (
                context.pointer_version, context.manifest_digest, context.stage):
            raise AuthorityUnavailable('C09 Contact control pointer changed')
        rows = tuple(protected.execute('SELECT prepared_original_json FROM c09_storage_operations_v1 '
            'WHERE installation_id=? AND generation<=? ORDER BY generation',
            (control.installation_id, context.storage_generation)))
    found = None
    prior = None
    verified = []
    for (encoded,) in rows:
        if encoded is None:
            continue
        prepared = json.loads(encoded); control.verify_original_v1(prepared, 'prepared_digest')
        facts = read_execution_recovery_facts_v4_locked(db, prepared['namespace'], operation_id=prepared['operation_id'])
        pin = read_execution_recovery_facts_pin_v4_locked(db, prepared['namespace'], operation_id=prepared['operation_id'])
        bindings = read_recovery_bindings_v1_locked(db, namespace=prepared['namespace'], operation_id=prepared['operation_id'])
        if (facts is None or pin is None or bindings is None
                or prepared['facts_digest'] != facts.facts_digest
                or prepared['facts_pin_original'] != asdict(pin)
                or prepared['recovery_bindings_digest'] != bindings.bindings_digest
                or bindings.prior_transition_digest_or_none != prior):
            raise AuthorityUnavailable('C09 Contact signed frame lineage differs')
        from .c09_recovery_frame_v5 import C09RecoveryFactFrameV5, verify_contact_finish_inventory_restore_v5
        if type(facts) is C09RecoveryFactFrameV5:
            inventory = verify_contact_finish_inventory_restore_v5(db, facts=facts, pin=pin,
                prepared=prepared, verified_prior=tuple(verified))
            originals = tuple(member.original for member in inventory.members)
        else:
            # Preserve the resolver's authenticated ordinary V4 zero branch.
            # No opaque graph commitment or archive can supply missing Contact
            # absence evidence, and this branch never issues a Contact member.
            if read_contact_finish_originals_v1(db,namespace=prepared['namespace'],operation_id=prepared['operation_id']) or facts.graph_facts:
                raise AuthorityUnavailable('C09 Contact legacy V4 lacks authenticated complete absence proof; HOLD')
            originals=()
        for original in originals:
            if original.namespace == namespace and original.business_operation_id == business_operation_id:
                if found is not None and found != original:
                    raise AuthorityUnavailable('C09 Contact archived business finish is ambiguous')
                found = original
        prior = prepared['prepared_digest']
        verified.append((prepared,facts,bindings))
    if found is None:
        raise AuthorityUnavailable('C09 Contact authenticated consumed finish absent; HOLD')
    return found


def capture_contact_finish_originals_v1(*, core_db, business, namespace_id, seal, verifier_commitment, registry,
                                       graph_facts, require_existing=False, storage_reader=None):
    """Called exclusively inside the actual installed/connection port freeze."""
    from .v2_fence_store import AuthorityV2FenceStore
    from .v2_contract import FencePermitV2, from_wire, canonical_digest as permit_digest
    from ..runtime.domain_production_originals_v1 import TABLE as ORIGINALS, read_adopted_domain_operation_v1
    from ..runtime.c09_contact_final_v1 import validate_contact_final_original_joins_v1
    if not core_db.in_transaction or not business.in_transaction:
        raise AuthorityUnavailable('C09 Contact needs actual frozen Core and business snapshots')
    if business.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (ORIGINALS,)).fetchone() is None:
        return ()
    operations = tuple(row[0] for row in business.execute(f'SELECT operation_id FROM {ORIGINALS} '
        "WHERE bot=? AND persona=? AND domain='d08' AND operation_kind IN ('prepare_contact_dispatch','prepare_contact_dispatch_v3') ORDER BY operation_id LIMIT 1025",
        namespace_id.as_tuple))
    if len(operations)>1024:
        raise AuthorityUnavailable('C09 Contact complete business inventory exceeds finite bound; HOLD')
    if not operations:
        return ()
    if not require_existing:
        install_contact_finish_archive_v1(core_db)
    facts = {fact.operation_id: fact for fact in graph_facts}
    result = []
    for operation in operations:
        production = read_adopted_domain_operation_v1(business, namespace_id, operation)
        evidence = validate_contact_final_original_joins_v1(business, namespace=namespace_id,
            operation_id=operation, payload=production['payload'], receipt=production['receipt'],
            original_digest=production['original_digest'], registry=registry)
        attempt = business.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?', (*namespace_id.as_tuple, operation)).fetchone()
        if attempt is None or attempt[2] is None:
            raise AuthorityUnavailable('C09 Contact actual Owner attempt absent; HOLD')
        expected_attempt = 'owner-domain-' + canonical_digest((namespace_id, operation, attempt[0]))[:48]
        permit = from_wire(json.loads(attempt[2]))
        row = AuthorityV2FenceStore._row(core_db, expected_attempt)
        finish_digest = 'sha256:' + canonical_digest({'schema': 'w01.owner-domain-write.v3',
            'operation_id': operation, 'request_digest': attempt[0], 'permit_token': permit.token})
        if type(permit) is not FencePermitV2 or attempt[1] != expected_attempt:
            raise AuthorityUnavailable('C09 Contact typed Owner permit identity differs')
        if row is None:
            original = _read_authenticated_archived_contact_v1(core_db, control=storage_reader,
                namespace=seal.namespace, business_operation_id=operation)
            proof = production['payload']['provenance']; fact = facts.get(operation)
            if (original.authority_id != seal.authority_id or original.installation_id != seal.installation_id
                    or original.business_namespace_digest != canonical_digest(namespace_id)
                    or original.owner_attempt_id != expected_attempt or original.owner_request_digest != attempt[0]
                    or original.permit_digest != permit_digest(permit).removeprefix('sha256:')
                    or original.generation != evidence.activation_generation
                    or original.finish_request_digest != finish_digest
                    or original.business_original_digest != production['original_digest']
                    or original.business_receipt_digest != canonical_digest(production['receipt'])
                    or original.qualification_evidence_digest != canonical_digest(evidence)
                    or original.qualification_digest != proof['qualification_digest']
                    or fact is None or (fact.receipt_commitment, fact.write_set_commitment, fact.unresolved_obligation_commitment)
                        != (original.graph_receipt_commitment, original.graph_write_set_commitment,
                            original.unresolved_obligation_commitment)
                    or original.write_commitments != tuple(sorted((canonical_digest(m['ref']), m['revision'], m['digest'])
                        for m in proof['write_commitments']))):
                raise AuthorityUnavailable('C09 Contact current business differs from authenticated consumed finish')
            result.append(original)
            continue
        if (AuthorityV2FenceStore._permit(row) != permit or permit.operation != 'write'
                or (permit.authority_id, permit.namespace, permit.generation) !=
                (seal.authority_id, seal.namespace, evidence.activation_generation)
                or row[6] != 'finished' or row[8:11] != ('finish:' + expected_attempt, finish_digest, None)):
            raise AuthorityUnavailable('C09 Contact true finished Owner fence absent or different; HOLD')
        columns = tuple(r[1] for r in core_db.execute('PRAGMA table_info(authority_v2_fences)'))
        actual_row = core_db.execute('SELECT * FROM authority_v2_fences WHERE operation_id=?', (expected_attempt,)).fetchone()
        from .c09_authority_storage_rebase import _row_commitment
        fact = facts.get(operation)
        if fact is None:
            raise AuthorityUnavailable('C09 Contact actual Graph fact absent')
        proof = production['payload']['provenance']
        from .c09_connection_state_v1 import anchor_in_tx_v1
        observed_anchor = anchor_in_tx_v1(core_db, seal.namespace)
        if (observed_anchor.authority_id != seal.authority_id
                or (observed_anchor.execution_journal_id, observed_anchor.execution_seq, observed_anchor.execution_digest)
                != (seal.execution_journal_id, seal.execution_seq, seal.execution_digest)):
            raise AuthorityUnavailable('C09 Contact actual Core observation head differs from verified source seal')
        body = dict(authority_id=seal.authority_id, installation_id=seal.installation_id,
            namespace=seal.namespace, operation_id=seal.operation_id, business_operation_id=operation,
            business_namespace_digest=canonical_digest(namespace_id), owner_attempt_id=expected_attempt,
            owner_request_digest=attempt[0], permit_digest=permit_digest(permit).removeprefix('sha256:'),
            permit_subject_digest=canonical_digest(permit.subject), permit_holder_digest=canonical_digest(permit.holder),
            permit_token_digest=hashlib.sha256(permit.token.encode()).hexdigest(), generation=permit.generation,
            fence_epoch=permit.fence_epoch, fence_revision=permit.revision, pinned_anchor=permit.pinned_anchor,
            observed_core_anchor=observed_anchor,
            finish_request_id='finish:' + expected_attempt, finish_request_digest=finish_digest,
            fence_row_commitment=_row_commitment('authority_v2_fences', columns, actual_row),
            business_original_digest=production['original_digest'], business_receipt_digest=canonical_digest(production['receipt']),
            graph_receipt_commitment=fact.receipt_commitment, graph_write_set_commitment=fact.write_set_commitment,
            unresolved_obligation_commitment=fact.unresolved_obligation_commitment,
            qualification_digest=proof['qualification_digest'], qualification_evidence_digest=canonical_digest(evidence),
            write_commitments=tuple(sorted((canonical_digest(member['ref']), member['revision'], member['digest'])
                for member in proof['write_commitments'])), observed_journal_id=seal.execution_journal_id,
            observed_execution_seq=seal.execution_seq, observed_execution_digest=seal.execution_digest,
            source_seal_digest=seal.seal_digest, verifier_commitment=verifier_commitment,
            schema='sylanne3.c09.contact-finish-original.v1')
        ordered = tuple(body[f.name] for f in fields(C09ContactFinishOriginalV1) if f.name != 'original_digest')
        original = C09ContactFinishOriginalV1(**body, original_digest=canonical_digest(ordered))
        encoded = canonical_serialize(asdict(original))
        old = core_db.execute(f'SELECT original_json,original_digest FROM {TABLE} WHERE namespace=? AND operation_id=? AND business_operation_id=?',
            (seal.namespace, seal.operation_id, operation)).fetchone()
        if old is not None and old != (encoded, original.original_digest):
            raise AuthorityUnavailable('C09 Contact finish archive replay differs')
        if old is None:
            if require_existing:
                raise AuthorityUnavailable('C09 Contact finish archive absent from completed Core')
            core_db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?)',
                (seal.namespace, seal.operation_id, operation, encoded, original.original_digest))
        result.append(original)
    return tuple(result)


def verify_contact_finish_recovery_v1(db, *, original, facts, pin, prepared):
    """Reauthenticate archived observations through real signed frame joins."""
    from .c09_recovery_frame_v4 import C09ExecutionSourceSealV4
    row = db.execute('SELECT seal_json FROM authority_c09_execution_source_seals_v4 WHERE namespace=? AND operation_id=?',
        (original.namespace, original.operation_id)).fetchone()
    if row is None:
        raise AuthorityUnavailable('C09 Contact archived source seal absent')
    body = json.loads(row[0]); body['suffix_row_commitments'] = tuple(body['suffix_row_commitments'])
    seal = C09ExecutionSourceSealV4(**body)
    if (prepared['facts_digest'] != facts.facts_digest or prepared['facts_pin_original'] != asdict(pin)
            or (facts.authority_id, facts.installation_id, facts.namespace, facts.operation_id) !=
            (original.authority_id, original.installation_id, original.namespace, original.operation_id)
            or pin.seal_digest != seal.seal_digest or original.source_seal_digest != seal.seal_digest
            or (original.observed_journal_id, original.observed_execution_seq, original.observed_execution_digest,
                original.verifier_commitment) != (pin.old_journal_id, pin.old_seq, pin.old_digest, pin.verifier_commitment)
            or tuple(f for f in facts.graph_facts if f.operation_id == original.business_operation_id)
                != (contact_graph_fact_v1(original),)):
        raise AuthorityUnavailable('C09 Contact finish is outside authenticated PREPARED facts/pin/source')
    transition = prepared['anchor_transition_original']
    if (prepared['old_core_anchor_original'] != asdict(original.observed_core_anchor)
            or transition['before_anchor'] != prepared['old_core_anchor_original']
            or transition['after_anchor'] != prepared['new_core_anchor_original']):
        raise AuthorityUnavailable('C09 Contact actual observed anchor/transition differs')
    consumed = db.execute('SELECT operation_id,original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 '
        "WHERE namespace=? AND kind='fence' AND item_id=?", (original.namespace, original.owner_attempt_id)).fetchone()
    if consumed != (original.owner_attempt_id, original.fence_row_commitment, pin.pin_digest):
        raise AuthorityUnavailable('C09 Contact finish consumed fence differs')
    if db.execute('SELECT 1 FROM authority_v2_fences WHERE operation_id=?', (original.owner_attempt_id,)).fetchone():
        raise AuthorityUnavailable('C09 Contact consumed fence unexpectedly survived')
    return original
