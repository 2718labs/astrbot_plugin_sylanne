"""Explicit carrier inventory version including independent frame originals.

V1's 19-family wire remains historical. V2 freezes twenty actual SQL families;
this still does not attest candidate disposal or disappearance of backup files.
"""
from dataclasses import dataclass, fields

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable
from .c09_contact_disposition_v1 import (
    CARRIER_FAMILIES as V1_FAMILIES, MAX_CARRIER_ROWS, ContactCarrierRowV1,
    _hash, _committed, _capture_issued_contact_carriers_v1, _ISSUED_CARRIERS,
)
from .c09_contact_frame_authentication_v1 import TABLE, COLUMNS, require_contact_frame_authentication_schema_v1

CARRIER_FAMILIES_V2 = tuple(sorted((*V1_FAMILIES, ('core', TABLE))))


@dataclass(frozen=True, slots=True)
class ContactCarrierFamilyV2:
    role: str
    table: str
    present: bool
    schema_commitment: str
    rows: tuple[ContactCarrierRowV1, ...]

    def __post_init__(self):
        if ((self.role, self.table) not in CARRIER_FAMILIES_V2 or type(self.present) is not bool
                or type(self.rows) is not tuple or len(self.rows) > MAX_CARRIER_ROWS
                or any(type(r) is not ContactCarrierRowV1 for r in self.rows)
                or tuple(r.locator_commitment for r in self.rows) != tuple(sorted({r.locator_commitment for r in self.rows}))
                or not self.present and self.rows):
            raise AuthorityUnavailable('C09 V2 exact carrier family differs')
        _hash(self.schema_commitment)
        if not self.present and self.schema_commitment != canonical_digest((self.role, self.table, 'absent')):
            raise AuthorityUnavailable('C09 V2 carrier negative inventory differs')


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ContactCarrierInventoryV2:
    namespace_commitment: str
    operation_commitment: str
    source_seal_digest: str
    current_manifest_digest: str
    source_files_commitment: str
    observed_generation: int
    observed_execution_seq: int
    families: tuple[ContactCarrierFamilyV2, ...]
    inventory_digest: str
    schema: str = 'sylanne3.c09.contact_carrier_inventory.v2'

    def __post_init__(self):
        if (self.schema != 'sylanne3.c09.contact_carrier_inventory.v2'
                or type(self.observed_generation) is not int or self.observed_generation < 1
                or type(self.observed_execution_seq) is not int or self.observed_execution_seq < 0
                or type(self.families) is not tuple or any(type(f) is not ContactCarrierFamilyV2 for f in self.families)
                or tuple((f.role, f.table) for f in self.families) != CARRIER_FAMILIES_V2):
            raise AuthorityUnavailable('C09 V2 complete carrier inventory differs')
        for name in ('namespace_commitment','operation_commitment','source_seal_digest',
                     'current_manifest_digest','source_files_commitment'):
            _hash(getattr(self, name))
        _committed(self, 'inventory_digest')


def decode_contact_carrier_inventory_v2(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ContactCarrierInventoryV2)}:
        raise AuthorityUnavailable('C09 V2 carrier closed wire differs')
    body = dict(raw)
    values = body['families']
    if type(values) is not list or len(values) != len(CARRIER_FAMILIES_V2):
        raise AuthorityUnavailable('C09 V2 carrier wire inventory bound differs')
    families = []
    for value in values:
        if type(value) is not dict or set(value) != {f.name for f in fields(ContactCarrierFamilyV2)}:
            raise AuthorityUnavailable('C09 V2 carrier family wire differs')
        value = dict(value)
        rows = value['rows']
        if type(rows) is not list or len(rows) > MAX_CARRIER_ROWS:
            raise AuthorityUnavailable('C09 V2 carrier wire rows exceed bound')
        if any(type(row) is not dict or set(row) != {'locator_commitment','row_commitment'} for row in rows):
            raise AuthorityUnavailable('C09 V2 carrier row wire differs')
        value['rows'] = tuple(ContactCarrierRowV1(**row) for row in rows)
        families.append(ContactCarrierFamilyV2(**value))
    body['families'] = tuple(families)
    return ContactCarrierInventoryV2(**body)


def _authentication_family_in_tx_v2(db, *, namespace):
    from .c09_authority_storage_rebase import _cell, _row_commitment
    from .c09_contact_frame_authentication_v1 import validate_contact_frame_authentication_row_v1
    if not db.in_transaction:
        raise AuthorityUnavailable('C09 V2 carrier actual Core transaction required')
    require_contact_frame_authentication_schema_v1(db)
    rows = db.execute(f'SELECT * FROM {TABLE} WHERE namespace_commitment=? LIMIT ?',
        (canonical_digest(('namespace', namespace)), MAX_CARRIER_ROWS + 1)).fetchall()
    if len(rows) > MAX_CARRIER_ROWS:
        raise AuthorityUnavailable('C09 frame authentication inventory exceeds complete bound; HOLD')
    commitments = []
    for row in rows:
        validate_contact_frame_authentication_row_v1(COLUMNS, row)
        commitments.append(ContactCarrierRowV1(canonical_digest(('core',TABLE,tuple(_cell(v) for v in row[:3]))),
            _row_commitment(TABLE,COLUMNS,tuple(row))))
    ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()[0]
    return ContactCarrierFamilyV2('core',TABLE,True,canonical_digest((ddl,COLUMNS)),
        tuple(sorted(commitments,key=lambda r:r.locator_commitment)))


def _capture_issued_contact_carriers_v2(port, *, inventory):
    """Same exact active issuer as V1; no ordinary DTO can supply a family."""
    old = _capture_issued_contact_carriers_v1(port, inventory=inventory)
    core_db = port._current(inventory.namespace, inventory.operation_id)[5]
    families = [ContactCarrierFamilyV2(f.role,f.table,f.present,f.schema_commitment,f.rows) for f in old.families]
    families.append(_authentication_family_in_tx_v2(core_db,namespace=inventory.namespace))
    values = {f.name:getattr(old,f.name) for f in fields(ContactCarrierInventoryV2)
        if f.name not in {'schema','families','inventory_digest'}}
    values['families'] = tuple(sorted(families,key=lambda f:(f.role,f.table)))
    values['inventory_digest'] = canonical_digest(tuple(values[f.name] if f.name in values else f.default
        for f in fields(ContactCarrierInventoryV2) if f.name != 'inventory_digest'))
    result = ContactCarrierInventoryV2(**values)
    _ISSUED_CARRIERS.pop(id(old),None)
    _ISSUED_CARRIERS[id(result)] = result
    port._contact_carrier_inventory_v1 = result
    return result
