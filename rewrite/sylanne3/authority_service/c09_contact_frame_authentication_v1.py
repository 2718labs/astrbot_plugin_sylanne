"""Independent opaque authentication of intact Contact frames before disposal.

Only the registered, active recovery freeze can issue these originals. This is
not an erased-member attestation: it authenticates the old complete frame so a
later actual disposition can replace covered payload without pretending its
sanitized JSON still has the old signature. No old PREPARED/body is archived.
"""
from dataclasses import asdict, dataclass, fields
import hashlib
import hmac
import json

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable

TABLE = 'authority_c09_contact_frame_authentications_v1'
COLUMNS = ('namespace_commitment', 'source_operation_commitment', 'frame_digest', 'original_json', 'original_digest')
DDL = (f'CREATE TABLE {TABLE}(namespace_commitment TEXT NOT NULL,source_operation_commitment TEXT NOT NULL,'
       'frame_digest TEXT NOT NULL,original_json TEXT NOT NULL,original_digest TEXT NOT NULL,'
       'PRIMARY KEY(namespace_commitment,source_operation_commitment,frame_digest)) STRICT')
SCHEMA = 'sylanne3.c09.authenticated_contact_frozen_frame.v1'
SIGNED_SCHEMA = 'sylanne3.c09.signed_contact_frozen_frame.v1'
MAX_HISTORY_FRAMES = 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024


def _hash(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise AuthorityUnavailable('C09 frozen-frame exact opaque commitment required')


@dataclass(frozen=True, slots=True)
class AuthenticatedContactFrozenFrameV1:
    authority_commitment: str
    installation_commitment: str
    namespace_commitment: str
    source_operation_commitment: str
    frame_operation_commitment: str
    origin: str
    frame_digest: str
    pin_digest: str
    inventory_digest: str
    source_seal_digest: str
    prepared_digest: str | None
    old_signature_commitment: str | None
    member_commitments: tuple[str, ...]
    producing_generation: int
    observed_generation: int
    observation_seq: int
    observation_anchor_digest: str
    authentication_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or self.origin not in {'actual_unswitched_freeze', 'signed_prepared_history'}
                or type(self.producing_generation) is not int or self.producing_generation < 1
                or type(self.observed_generation) is not int or self.observed_generation < self.producing_generation
                or type(self.observation_seq) is not int or self.observation_seq < 0
                or type(self.member_commitments) is not tuple or len(self.member_commitments) > 1024
                or any(type(v) is not str for v in self.member_commitments)
                or self.member_commitments != tuple(sorted(set(self.member_commitments)))):
            raise AuthorityUnavailable('C09 frozen-frame exact origin/generation/member inventory differs')
        for name in ('authority_commitment', 'installation_commitment', 'namespace_commitment',
                     'source_operation_commitment', 'frame_operation_commitment', 'frame_digest', 'pin_digest',
                     'inventory_digest', 'source_seal_digest', 'observation_anchor_digest'):
            _hash(getattr(self, name))
        for member in self.member_commitments:
            _hash(member)
        if self.origin == 'actual_unswitched_freeze':
            if (self.prepared_digest is not None or self.old_signature_commitment is not None
                    or self.producing_generation != self.observed_generation
                    or self.frame_operation_commitment != self.source_operation_commitment):
                raise AuthorityUnavailable('C09 current freeze cannot invent an old PREPARED signature')
        else:
            _hash(self.prepared_digest)
            _hash(self.old_signature_commitment)
        _hash(self.authentication_digest)
        if self.authentication_digest != canonical_digest(tuple(getattr(self, f.name) for f in fields(self)
                if f.name != 'authentication_digest')):
            raise AuthorityUnavailable('C09 frozen-frame canonical authentication differs')


@dataclass(frozen=True, slots=True)
class SignedContactFrozenFrameV1:
    authentication: AuthenticatedContactFrozenFrameV1
    key_commitment: str
    original_digest: str
    signature: str
    schema: str = SIGNED_SCHEMA

    def __post_init__(self):
        if self.schema != SIGNED_SCHEMA or type(self.authentication) is not AuthenticatedContactFrozenFrameV1:
            raise AuthorityUnavailable('C09 frozen-frame signed closed type differs')
        for name in ('key_commitment', 'original_digest', 'signature'):
            _hash(getattr(self, name))
        if self.original_digest != canonical_digest((self.authentication, self.key_commitment, SIGNED_SCHEMA)):
            raise AuthorityUnavailable('C09 frozen-frame signed commitment differs')


def decode_contact_frame_authentication_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(SignedContactFrozenFrameV1)}:
        raise AuthorityUnavailable('C09 signed frame closed wire fields differ')
    body = dict(raw)
    payload = body['authentication']
    if type(payload) is not dict or set(payload) != {f.name for f in fields(AuthenticatedContactFrozenFrameV1)}:
        raise AuthorityUnavailable('C09 frame authentication closed wire fields differ')
    payload = dict(payload)
    members = payload['member_commitments']
    if type(members) is not list or len(members) > 1024:
        raise AuthorityUnavailable('C09 frame authentication wire inventory exceeds bound')
    payload['member_commitments'] = tuple(members)
    body['authentication'] = AuthenticatedContactFrozenFrameV1(**payload)
    return SignedContactFrozenFrameV1(**body)


def verify_contact_frame_authentication_v1(control, value):
    """Authenticate an original against the actual installed protected key."""
    from .c09_storage_control_v1 import C09StorageControlV1
    if type(control) is not C09StorageControlV1 or type(value) is not SignedContactFrozenFrameV1:
        raise AuthorityUnavailable('C09 installed control and typed frame authentication required')
    control.lease.require_held()
    if (value.key_commitment != canonical_digest(('c09.key', control.key_id))
            or value.authentication.authority_commitment != canonical_digest(('authority', control.authority_id))
            or value.authentication.installation_commitment != canonical_digest(('installation', control.installation_id))):
        raise AuthorityUnavailable('C09 authenticated frozen frame installed identity differs')
    expected = hmac.new(control._key, (SIGNED_SCHEMA + '\n' + value.original_digest).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, value.signature):
        raise AuthorityUnavailable('C09 authenticated frozen frame installed signature differs')
    return value


def _trigger(action):
    return (f'CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} '
            "BEGIN SELECT RAISE(ABORT,'C09 frozen frame immutable'); END")


def install_contact_frame_authentication_schema_v1(db):
    if not db.in_transaction:
        raise AuthorityUnavailable('C09 frame authentication needs the actual Core transaction')
    db.execute(DDL.replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', 1))
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() != (DDL,):
        raise AuthorityUnavailable('C09 frame authentication Core schema differs')
    for action in ('UPDATE', 'DELETE'):
        name = TABLE + '_no_' + action.lower()
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None:
            db.execute(_trigger(action))
        elif row != (_trigger(action),):
            raise AuthorityUnavailable('C09 frame authentication immutable trigger differs')


def require_contact_frame_authentication_schema_v1(db):
    if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() != (DDL,):
        raise AuthorityUnavailable('C09 frame authentication Core schema differs')
    for action in ('UPDATE', 'DELETE'):
        if db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                      (TABLE + '_no_' + action.lower(),)).fetchone() != (_trigger(action),):
            raise AuthorityUnavailable('C09 frame authentication immutable trigger differs')


def validate_contact_frame_authentication_row_v1(columns, row):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise AuthorityUnavailable('C09 frame authentication installed row columns differ')
    value = decode_contact_frame_authentication_v1(json.loads(row[3]))
    a = value.authentication
    if tuple(row) != (a.namespace_commitment, a.source_operation_commitment, a.frame_digest,
                      canonical_serialize(asdict(value)), value.original_digest):
        raise AuthorityUnavailable('C09 frame authentication actual canonical SQL row differs')
    return value


def _issue_authenticated_contact_frames_v1(port, *, facts, pin):
    """Real pre-disposal private issuer; public DTOs cannot invoke this scope.

    The private V5 issuer and the installed resolver authenticate full current
    and historical inventories respectively. Only opaque commitments leave
    that verification. The observation is this actual freeze, not a fabricated
    historical finish event or a future SQL disposal acknowledgement.
    """
    from .c09_contact_finish_original_v1 import _PORTS
    from .c09_recovery_frame_v5 import C09RecoveryFactFrameV5, _ISSUED_INVENTORIES, _make_issued_frame_v5
    from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
    from .c09_connection_state_v1 import anchor_in_tx_v1
    if _PORTS.get(id(port)) is not port or type(facts) is not C09RecoveryFactFrameV5:
        raise AuthorityUnavailable('C09 authenticated frozen frame requires the actual private installation port')
    inventory = facts.contact_finish_inventory
    if _ISSUED_INVENTORIES.get(id(inventory)) is not inventory:
        raise AuthorityUnavailable('C09 authenticated frozen frame inventory was not issued here')
    seal, _old, _rows, _verifier, business, db = port._current(inventory.namespace, inventory.operation_id)
    if not db.in_transaction or not business.in_transaction:
        raise AuthorityUnavailable('C09 authenticated frozen frame snapshots closed')
    expected_facts, expected_pin = _make_issued_frame_v5(port, ordinary_facts=facts.ordinary_facts,
        inventory=inventory, seal=seal)
    if facts != expected_facts or pin != expected_pin:
        raise AuthorityUnavailable('C09 authenticated frozen frame differs from this issued snapshot')
    control = port._contact_control
    with control._db() as protected:
        control._current(protected)
        sizes = protected.execute('SELECT length(CAST(prepared_original_json AS BLOB)) '
            'FROM c09_storage_operations_v1 WHERE installation_id=? LIMIT ?',
            (control.installation_id, MAX_HISTORY_FRAMES + 1)).fetchall()
        if (len(sizes) > MAX_HISTORY_FRAMES or any(row[0] is None for row in sizes)
                or sum(row[0] for row in sizes) > MAX_HISTORY_BYTES):
            raise AuthorityUnavailable('C09 authenticated frozen history exceeds complete resource bound; HOLD')
    context, history = InstalledSanitizedRecoveryResolverV4(storage_reader=control).read_verified_frames_v4()
    intent = control.read_operation_event_v1(seal.operation_id, 'INTENT')
    if (context.stage, context.pointer_version) != ('INTENT', intent['pointer_version']):
        raise AuthorityUnavailable('C09 authenticated frozen frame protected pointer changed')
    observation = anchor_in_tx_v1(db, seal.namespace)
    if observation != inventory.observed_core_anchor:
        raise AuthorityUnavailable('C09 authenticated frozen frame current observation drifted')
    frames = [(None, facts, pin)]
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked
    for prepared, historical, _bindings in history:
        if historical.namespace != seal.namespace:
            raise AuthorityUnavailable('C09 frozen history namespace differs')
        if type(historical) is C09RecoveryFactFrameV5:
            old_pin = read_execution_recovery_facts_pin_v4_locked(db, seal.namespace, operation_id=historical.operation_id)
            if old_pin is None:
                raise AuthorityUnavailable('C09 authenticated old frame pin disappeared')
            frames.append((prepared, historical, old_pin))
    install_contact_frame_authentication_schema_v1(db)
    result = []
    for prepared, frame, source_pin in frames:
        inv = frame.contact_finish_inventory
        values = dict(authority_commitment=canonical_digest(('authority', control.authority_id)),
            installation_commitment=canonical_digest(('installation', control.installation_id)),
            namespace_commitment=canonical_digest(('namespace', seal.namespace)),
            source_operation_commitment=canonical_digest(('operation', seal.operation_id)),
            frame_operation_commitment=canonical_digest(('operation', frame.operation_id)),
            origin='actual_unswitched_freeze' if prepared is None else 'signed_prepared_history',
            frame_digest=frame.facts_digest, pin_digest=source_pin.pin_digest, inventory_digest=inv.inventory_digest,
            source_seal_digest=source_pin.seal_digest,
            prepared_digest=None if prepared is None else prepared['prepared_digest'],
            old_signature_commitment=None if prepared is None else canonical_digest(prepared['signature']),
            member_commitments=tuple(sorted(canonical_digest(member.locator) for member in inv.members)),
            producing_generation=inv.observed_core_anchor.activation_generation,
            observed_generation=observation.activation_generation, observation_seq=observation.execution_seq,
            observation_anchor_digest=canonical_digest(observation))
        values['authentication_digest'] = canonical_digest(tuple(values[f.name] if f.name in values else f.default
            for f in fields(AuthenticatedContactFrozenFrameV1) if f.name != 'authentication_digest'))
        authentication = AuthenticatedContactFrozenFrameV1(**values)
        key = canonical_digest(('c09.key', control.key_id))
        original_digest = canonical_digest((authentication, key, SIGNED_SCHEMA))
        signature = hmac.new(control._key, (SIGNED_SCHEMA + '\n' + original_digest).encode(), hashlib.sha256).hexdigest()
        original = SignedContactFrozenFrameV1(authentication, key, original_digest, signature)
        verify_contact_frame_authentication_v1(control, original)
        row = (authentication.namespace_commitment, authentication.source_operation_commitment,
               authentication.frame_digest, canonical_serialize(asdict(original)), original.original_digest)
        existing = db.execute(f'SELECT * FROM {TABLE} WHERE namespace_commitment=? '
            'AND source_operation_commitment=? AND frame_digest=?', row[:3]).fetchone()
        if existing is None:
            db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?)', row)
        elif tuple(existing) != row:
            raise AuthorityUnavailable('C09 independently authenticated old frame original conflict')
        result.append(original)
    return tuple(result)
