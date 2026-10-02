"""Opaque Contact disposal contracts and actual-freeze carrier enumeration.

A codec is not an issuer. These values retain commitments, not copies of old
PREPARED JSON, paths, Contact originals or model text. Hashes remain covered
locators: they are not asserted to be anonymous. Physical disposal and restore
must join an issued value to the actual candidate transaction and new PREPARED.
"""
from dataclasses import dataclass, fields
from weakref import WeakValueDictionary

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable
from .c09_originals_archive_v1 import SINGLETONS

MAX_CARRIER_ROWS = 4096
MAX_MEMBERS = 1024
CARRIER_FAMILIES = tuple(sorted((
    *(("core", name) for name in SINGLETONS),
    ("core", "authority_c09_originals_archive_v1"),
    ("core", "authority_c09_recovery_fact_frames_v4"),
    ("core", "authority_c09_execution_source_seals_v4"),
    ("core", "authority_c09_execution_source_pins_v4"),
    ("core", "authority_c09_recovery_bindings_v1"),
    ("core", "authority_c09_contact_finish_originals_v1"),
    ("control", "c09_storage_operations_v1"),
    ("control", "c09_storage_manifests_v1"),
    ("control", "c09_storage_events_v1"),
    ("control", "c09_storage_current_v1"),
    ("control", "c09_storage_surface_evidence_v1"),
    ("control", "c09_storage_retired_files_v1"),
    ("control", "c09_storage_build_originals_v1"),
)))
_ISSUED_CARRIERS = WeakValueDictionary()


def _hash(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise AuthorityUnavailable("C09 Contact disposal exact opaque commitment required")


def _committed(value, name):
    _hash(getattr(value, name))
    if getattr(value, name) != canonical_digest(tuple(getattr(value, f.name) for f in fields(value) if f.name != name)):
        raise AuthorityUnavailable("C09 Contact disposal canonical commitment differs")


def _hashes(values, *, nonempty=False):
    if (type(values) is not tuple or any(type(v) is not str for v in values)
            or len(values) > MAX_MEMBERS or nonempty and not values
            or values != tuple(sorted(set(values)))):
        raise AuthorityUnavailable("C09 Contact disposal bounded unique commitment inventory differs")
    for value in values:
        _hash(value)


@dataclass(frozen=True, slots=True)
class ContactCarrierRowV1:
    locator_commitment: str
    row_commitment: str

    def __post_init__(self):
        _hash(self.locator_commitment)
        _hash(self.row_commitment)


@dataclass(frozen=True, slots=True)
class ContactCarrierFamilyV1:
    role: str
    table: str
    present: bool
    schema_commitment: str
    rows: tuple[ContactCarrierRowV1, ...]

    def __post_init__(self):
        if ((self.role, self.table) not in CARRIER_FAMILIES or type(self.present) is not bool
                or type(self.rows) is not tuple or len(self.rows) > MAX_CARRIER_ROWS
                or any(type(r) is not ContactCarrierRowV1 for r in self.rows)
                or tuple(r.locator_commitment for r in self.rows) != tuple(sorted({r.locator_commitment for r in self.rows}))
                or not self.present and self.rows):
            raise AuthorityUnavailable("C09 Contact disposal carrier family differs")
        _hash(self.schema_commitment)
        if not self.present and self.schema_commitment != canonical_digest((self.role, self.table, "absent")):
            raise AuthorityUnavailable("C09 Contact disposal absent carrier proof differs")


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContactCarrierInventoryV1:
    namespace_commitment: str
    operation_commitment: str
    source_seal_digest: str
    current_manifest_digest: str
    source_files_commitment: str
    observed_generation: int
    observed_execution_seq: int
    families: tuple[ContactCarrierFamilyV1, ...]
    inventory_digest: str
    schema: str = "sylanne3.c09.contact_carrier_inventory.v1"

    def __post_init__(self):
        if (self.schema != "sylanne3.c09.contact_carrier_inventory.v1"
                or type(self.observed_generation) is not int or self.observed_generation < 1
                or type(self.observed_execution_seq) is not int or self.observed_execution_seq < 0
                or type(self.families) is not tuple or any(type(f) is not ContactCarrierFamilyV1 for f in self.families)
                or tuple((f.role, f.table) for f in self.families) != CARRIER_FAMILIES):
            raise AuthorityUnavailable("C09 Contact disposal complete carrier inventory differs")
        for name in ("namespace_commitment", "operation_commitment", "source_seal_digest",
                     "current_manifest_digest", "source_files_commitment"):
            _hash(getattr(self, name))
        _committed(self, "inventory_digest")


@dataclass(frozen=True, slots=True)
class ContactErasedMemberAttestationV1:
    namespace_commitment: str
    business_operation_commitment: str
    original_digest: str
    old_frame_digest: str
    old_prepared_digest: str
    old_signature_commitment: str
    old_member_commitment: str
    coverage_commitment: str
    consumed_fence_commitment: str
    carrier_inventory_digest: str
    disposal_manifest_digest: str
    disposition_transaction_commitment: str
    new_generation: int
    observation_seq: int
    attestation_digest: str
    schema: str = "sylanne3.c09.contact_erased_member.v1"

    def __post_init__(self):
        if (self.schema != "sylanne3.c09.contact_erased_member.v1"
                or type(self.new_generation) is not int or self.new_generation < 1
                or type(self.observation_seq) is not int or self.observation_seq < 0):
            raise AuthorityUnavailable("C09 Contact erased member disposition scope differs")
        for f in fields(self):
            if f.name not in {"schema", "new_generation", "observation_seq", "attestation_digest"}:
                _hash(getattr(self, f.name))
        _committed(self, "attestation_digest")


@dataclass(frozen=True, slots=True)
class SanitizedContactHistoricalCarrierV1:
    old_frame_digest: str
    old_prepared_digest: str
    old_signature_commitment: str
    old_inventory_digest: str
    old_member_commitments: tuple[str, ...]
    retained_member_commitments: tuple[str, ...]
    erased_members: tuple[ContactErasedMemberAttestationV1, ...]
    carrier_inventory_digest: str
    new_generation: int
    observation_seq: int
    carrier_digest: str
    schema: str = "sylanne3.c09.sanitized_contact_historical_carrier.v1"

    def __post_init__(self):
        if (self.schema != "sylanne3.c09.sanitized_contact_historical_carrier.v1"
                or type(self.new_generation) is not int or self.new_generation < 1
                or type(self.observation_seq) is not int or self.observation_seq < 0
                or type(self.erased_members) is not tuple or not self.erased_members
                or len(self.erased_members) > MAX_MEMBERS
                or any(type(m) is not ContactErasedMemberAttestationV1 for m in self.erased_members)):
            raise AuthorityUnavailable("C09 Contact sanitized historical carrier scope differs")
        for name in ("old_frame_digest", "old_prepared_digest", "old_signature_commitment",
                     "old_inventory_digest", "carrier_inventory_digest"):
            _hash(getattr(self, name))
        _hashes(self.old_member_commitments, nonempty=True)
        _hashes(self.retained_member_commitments)
        erased = tuple(m.old_member_commitment for m in self.erased_members)
        _hashes(erased, nonempty=True)
        if (set(erased) & set(self.retained_member_commitments)
                or tuple(sorted((*erased, *self.retained_member_commitments))) != self.old_member_commitments):
            raise AuthorityUnavailable("C09 Contact retained/erased partition omits or substitutes old members")
        for m in self.erased_members:
            if (m.old_frame_digest, m.old_prepared_digest, m.old_signature_commitment,
                    m.carrier_inventory_digest, m.new_generation, m.observation_seq) != (
                    self.old_frame_digest, self.old_prepared_digest, self.old_signature_commitment,
                    self.carrier_inventory_digest, self.new_generation, self.observation_seq):
                raise AuthorityUnavailable("C09 Contact erased member is not this historical disposition")
        _committed(self, "carrier_digest")


def _decode(raw, kind):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise AuthorityUnavailable("C09 Contact disposal closed wire fields differ")
    body = dict(raw)
    if kind is ContactCarrierInventoryV1:
        _wire_array(body["families"], len(CARRIER_FAMILIES))
        body["families"] = tuple(_decode(v, ContactCarrierFamilyV1) for v in body["families"])
    elif kind is ContactCarrierFamilyV1:
        _wire_array(body["rows"], MAX_CARRIER_ROWS)
        body["rows"] = tuple(_decode(v, ContactCarrierRowV1) for v in body["rows"])
    elif kind is SanitizedContactHistoricalCarrierV1:
        for name in ("old_member_commitments", "retained_member_commitments", "erased_members"):
            _wire_array(body[name], MAX_MEMBERS)
        body["old_member_commitments"] = tuple(body["old_member_commitments"])
        body["retained_member_commitments"] = tuple(body["retained_member_commitments"])
        body["erased_members"] = tuple(_decode(v, ContactErasedMemberAttestationV1) for v in body["erased_members"])
    return kind(**body)


def _wire_array(value, limit):
    if type(value) is not list or len(value) > limit:
        raise AuthorityUnavailable("C09 Contact disposal wire array is not closed and bounded")


def decode_contact_disposition_v1(raw):
    kinds = {f.default: kind for kind in (ContactCarrierInventoryV1, ContactErasedMemberAttestationV1,
             SanitizedContactHistoricalCarrierV1) for f in fields(kind) if f.name == "schema"}
    if type(raw) is not dict or raw.get("schema") not in kinds:
        raise AuthorityUnavailable("C09 Contact disposal wire version differs")
    return _decode(raw, kinds[raw["schema"]])


def _carrier_family_in_tx_v1(db, *, role, table, namespace, installation_id):
    """Full bounded SQL enumeration; absent tables are explicit negative facts."""
    if not db.in_transaction or (role, table) not in CARRIER_FAMILIES:
        raise AuthorityUnavailable("C09 Contact carrier requires the pinned known SQL family")
    found = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
    if found is None:
        return ContactCarrierFamilyV1(role, table, False, canonical_digest((role, table, "absent")), ())
    columns = tuple(r[1] for r in db.execute(f'PRAGMA table_info("{table}")'))
    if role == "control" and table == "c09_storage_surface_evidence_v1":
        if "operation_id" not in columns:
            raise AuthorityUnavailable("C09 Contact carrier surface operation identity absent")
        if db.execute('SELECT 1 FROM c09_storage_surface_evidence_v1 AS evidence '
                'LEFT JOIN c09_storage_operations_v1 AS operation ON evidence.operation_id=operation.operation_id '
                'WHERE operation.operation_id IS NULL LIMIT 1').fetchone() is not None:
            raise AuthorityUnavailable("C09 Contact carrier orphan surface cannot prove complete absence; HOLD")
        rows = db.execute('SELECT evidence.* FROM c09_storage_surface_evidence_v1 AS evidence '
            'JOIN c09_storage_operations_v1 AS operation ON evidence.operation_id=operation.operation_id '
            'WHERE operation.installation_id=? LIMIT ?', (installation_id, MAX_CARRIER_ROWS + 1)).fetchall()
    else:
        selector, value = ("installation_id", installation_id) if role == "control" else ("namespace", namespace)
        if selector not in columns:
            raise AuthorityUnavailable("C09 Contact carrier actual SQL identity column absent")
        rows = db.execute(f'SELECT * FROM "{table}" WHERE "{selector}"=? LIMIT ?',
                          (value, MAX_CARRIER_ROWS + 1)).fetchall()
    if len(rows) > MAX_CARRIER_ROWS:
        raise AuthorityUnavailable("C09 Contact carrier SQL inventory exceeds finite limit; HOLD")
    from .c09_authority_storage_rebase import _row_commitment, _cell
    pk = tuple(r[1] for r in sorted(db.execute(f'PRAGMA table_info("{table}")'), key=lambda r: r[5]) if r[5])
    if not pk:
        raise AuthorityUnavailable("C09 Contact carrier SQL lacks an exact primary key")
    commitments = tuple(sorted((ContactCarrierRowV1(
        canonical_digest((role, table, tuple(_cell(row[columns.index(k)]) for k in pk))),
        _row_commitment(table, columns, tuple(row))) for row in rows), key=lambda r: r.locator_commitment))
    return ContactCarrierFamilyV1(role, table, True, canonical_digest((found[0], columns)), commitments)


def _capture_issued_contact_carriers_v1(port, *, inventory):
    """Only called while the real V5 issuer owns both frozen snapshots.

    This issues a bounded carrier *inventory*, not a deletion attestation.
    No candidate row is erased and no caller DTO supplies an empty inventory.
    """
    from .c09_contact_finish_original_v1 import _PORTS
    from .c09_recovery_frame_v5 import _ISSUED_INVENTORIES
    from .c09_connection_state_v1 import anchor_in_tx_v1
    if (_PORTS.get(id(port)) is not port or _ISSUED_INVENTORIES.get(id(inventory)) is not inventory
            or getattr(port, "_contact_finish_inventory_v5", None) is not inventory):
        raise AuthorityUnavailable("C09 Contact carrier issuer is not the actual freeze")
    seal, _old, _rows, _verifier, business, core_db = port._current(inventory.namespace, inventory.operation_id)
    if not business.in_transaction or not core_db.in_transaction:
        raise AuthorityUnavailable("C09 Contact carrier snapshots closed")
    anchor = anchor_in_tx_v1(core_db, seal.namespace)
    if anchor != inventory.observed_core_anchor:
        raise AuthorityUnavailable("C09 Contact carrier actual observation drifted")
    control = port._contact_control
    context = control.read_verified_current_storage_v1(verify_files=False)
    intent = control.read_operation_event_v1(seal.operation_id, "INTENT")
    if (context.stage, context.pointer_version) != ("INTENT", intent["pointer_version"]):
        raise AuthorityUnavailable("C09 Contact carrier source is not the exact INTENT")
    families = [_carrier_family_in_tx_v1(core_db, role=role, table=table,
        namespace=seal.namespace, installation_id=seal.installation_id)
        for role, table in CARRIER_FAMILIES if role == "core"]
    with control._db() as db:
        control._current(db)
        families.extend(_carrier_family_in_tx_v1(db, role=role, table=table,
            namespace=seal.namespace, installation_id=seal.installation_id)
            for role, table in CARRIER_FAMILIES if role == "control")
    values = dict(namespace_commitment=canonical_digest(("namespace", seal.namespace)),
        operation_commitment=canonical_digest(("operation", seal.operation_id)), source_seal_digest=seal.seal_digest,
        current_manifest_digest=context.manifest_digest, source_files_commitment=canonical_digest(context.manifest["members"]),
        observed_generation=anchor.activation_generation, observed_execution_seq=anchor.execution_seq,
        families=tuple(sorted(families, key=lambda f: (f.role, f.table))), inventory_digest="0" * 64)
    # Compute the exact typed wire without constructing a value with a fake digest.
    values["inventory_digest"] = canonical_digest(tuple(values[f.name] if f.name in values else f.default
        for f in fields(ContactCarrierInventoryV1) if f.name != "inventory_digest"))
    result = ContactCarrierInventoryV1(**values)
    _ISSUED_CARRIERS[id(result)] = result
    port._contact_carrier_inventory_v1 = result
    return result


def require_issued_contact_carriers_v1(port, value):
    if (_ISSUED_CARRIERS.get(id(value)) is not value or getattr(port, "_contact_carrier_inventory_v1", None) is not value
            or getattr(port, "_snapshot", None) is None):
        raise AuthorityUnavailable("C09 Contact carrier DTO is not an active issued disposal input")
    return value


def _revoke_contact_carriers_v1(port):
    value = getattr(port, "_contact_carrier_inventory_v1", None)
    if value is not None:
        _ISSUED_CARRIERS.pop(id(value), None)
        port._contact_carrier_inventory_v1 = None
