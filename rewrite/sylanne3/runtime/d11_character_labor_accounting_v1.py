"""Content-free accounting basis issued by the actual character-labor C commit.

The independent signature attests verified producer membership. It preserves
historical duration inputs and grants no Body read, claim, execution or budget.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d02.character_labor_v1 import (
    CharacterLaborPolicyV1, CharacterLaborQuoteV1,
    character_labor_policy_from_wire_v1, character_labor_quote_from_wire_v1,
)
from ..graph_types import AtomKey, Owner
from ..runtime_contracts import NamespaceId, CommitReceipt, canonical_digest, canonical_serialize
from .clock import _mapping_from_dict, _mapping_dict
from .issuers import D11BudgetJobIssuer

KIND = "character_labor_accounting_basis_v1"
SCHEMA = "d11.character-labor-accounting-basis.v1"
SIGN_KIND = "d11.character-labor-accounting-basis.v1"
MEMBERSHIP_SCHEMA = "d11.verified-character-labor-C-membership.v1"
TABLE = "graph_d11_life_originals_v1"
COLUMNS = ("bot", "persona", "kind", "original_ref", "producing_operation_id",
    "payload_json", "payload_digest", "signature")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("actual character-labor accounting commitment required")


def _closed(raw, cls):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("exact character-labor accounting fields required")
    return dict(raw)


@dataclass(frozen=True, slots=True)
class CharacterLaborColumnCommitmentV1:
    column: str
    sha256: str
    byte_count: int

    def __post_init__(self):
        _digest(self.sha256)
        if self.column not in ("reads", "revisions", "invalidated") or type(self.byte_count) is not int or self.byte_count < 2:
            raise ValueError("actual complete C event column commitment required")


@dataclass(frozen=True, slots=True)
class CharacterLaborCProducerMembershipV1:
    namespace: NamespaceId
    prepare_operation_id: str
    activity_id: str
    effect_id: str
    prepared_ref: str
    prepared_digest: str
    accounting_ref: str
    accounting_digest: str
    receipt_digest: str
    operation_digest: str
    commit_seq: int
    event_digest: str
    graph_epoch: int
    job_ref: str
    job_revision: int
    job_value_sha256: str
    columns: tuple[CharacterLaborColumnCommitmentV1, ...]
    attestation_kind: str = "verified_character_labor_C_membership_v1"
    schema: str = MEMBERSHIP_SCHEMA

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.schema != MEMBERSHIP_SCHEMA
                or self.attestation_kind != "verified_character_labor_C_membership_v1"
                or type(self.commit_seq) is not int or self.commit_seq < 0
                or type(self.graph_epoch) is not int or self.graph_epoch < 1
                or type(self.job_revision) is not int or self.job_revision < 1
                or NamespaceId.from_key(AtomKey.from_token(self.job_ref)) != self.namespace
                or type(self.columns) is not tuple
                or tuple(c.column for c in self.columns) != ("reads", "revisions", "invalidated")
                or any(type(c) is not CharacterLaborColumnCommitmentV1 for c in self.columns)):
            raise ValueError("exact authenticated C membership assertion required")
        for value in (self.prepared_digest, self.accounting_digest, self.receipt_digest,
                self.operation_digest, self.event_digest, self.job_value_sha256):
            _digest(value)


@dataclass(frozen=True, slots=True)
class CharacterLaborAccountingBasisV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    execution_id: str
    effect_id: str
    binding_digest: str
    prepare_operation_id: str
    prepared_ref: str
    prepared_digest: str
    accounting_ref: str
    accounting_digest: str
    body_preparation_ref: str
    body_preparation_digest: str
    body_prepare_operation_id: str
    body_receipt_digest: str
    admission_ref: str
    admission_digest: str
    recipe_ref: str
    recipe_revision: int
    recipe_digest: str
    policy: CharacterLaborPolicyV1
    policy_digest: str
    quote: CharacterLaborQuoteV1
    quote_digest: str
    reservation_ref: str
    reservation_revision: int
    reservation_digest: str
    settlement_ref: str
    settlement_revision: int
    settlement_digest: str | None
    clock_mapping_json: str
    clock_original_digest: str
    receipt_digest: str
    membership: CharacterLaborCProducerMembershipV1
    usage: str = "historical_duration_only"
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or self.usage != "historical_duration_only"
                or type(self.namespace) is not NamespaceId
                or type(self.policy) is not CharacterLaborPolicyV1
                or type(self.quote) is not CharacterLaborQuoteV1
                or type(self.membership) is not CharacterLaborCProducerMembershipV1
                or type(self.recipe_revision) is not int or self.recipe_revision < 1
                or type(self.reservation_revision) is not int or self.reservation_revision < 1
                or self.settlement_revision != 0 or self.settlement_digest is not None):
            raise ValueError("exact content-free labor accounting basis required")
        for name in ("manifest_digest", "binding_digest", "prepared_digest", "accounting_digest",
                "body_preparation_digest", "body_receipt_digest", "admission_digest",
                "recipe_digest", "policy_digest", "quote_digest", "reservation_digest",
                "clock_original_digest", "receipt_digest"):
            _digest(getattr(self, name))
        if any(type(getattr(self, name)) is not str or not getattr(self, name)
                for name in ("authority_namespace", "authority_id", "installation_id", "execution_id",
                    "effect_id", "prepare_operation_id", "prepared_ref", "accounting_ref")):
            raise ValueError("actual Authority and C accounting identities required")
        p, q, m = self.policy, self.quote, self.membership
        if ((p.namespace, p.recipe_ref, p.recipe_revision, p.recipe_digest)
                    != (self.namespace, self.recipe_ref, self.recipe_revision, self.recipe_digest)
                or canonical_digest(plain_v1(p)) != self.policy_digest
                or canonical_digest(q) != self.quote_digest
                or (q.namespace, q.effect_id, q.policy_ref, q.policy_revision, q.policy_digest)
                    != (self.namespace, self.effect_id, p.policy_ref, p.revision, self.policy_digest)
                or self.body_preparation_ref != "character-labor-body:" + self.body_prepare_operation_id
                or self.admission_ref != "character-labor-admission:" + self.execution_id
                or (m.namespace, m.prepare_operation_id, m.effect_id, m.prepared_ref, m.prepared_digest,
                    m.accounting_ref, m.accounting_digest, m.receipt_digest)
                    != (self.namespace, self.prepare_operation_id, self.effect_id, self.prepared_ref,
                        self.prepared_digest, self.accounting_ref, self.accounting_digest, self.receipt_digest)):
            raise ValueError("labor accounting basis changed its signed producer or numeric contract")
        raw = json.loads(self.clock_mapping_json)
        mapping = _mapping_from_dict(raw)
        if (canonical_serialize(_mapping_dict(mapping)) != self.clock_mapping_json
                or (mapping.mapping_id, mapping.version, self.clock_original_digest)
                    != (q.clock_mapping_ref, q.clock_mapping_version, q.clock_original_digest)):
            raise ValueError("labor accounting basis must keep only the original scalar clock mapping")
        for ref, kind in ((self.reservation_ref, "d02.reservation.v1"), (self.settlement_ref, "d02.settlement.v1")):
            key = AtomKey.from_token(ref)
            if key.type_name != kind or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("labor accounting basis changed its actual D02 identity")


def character_labor_accounting_basis_from_wire_v1(raw):
    value = _closed(raw, CharacterLaborAccountingBasisV1)
    value["namespace"] = NamespaceId(**value["namespace"])
    value["policy"] = character_labor_policy_from_wire_v1(value["policy"])
    value["quote"] = character_labor_quote_from_wire_v1(value["quote"])
    m = _closed(value["membership"], CharacterLaborCProducerMembershipV1)
    m["namespace"] = NamespaceId(**m["namespace"])
    m["columns"] = tuple(CharacterLaborColumnCommitmentV1(**_closed(c, CharacterLaborColumnCommitmentV1))
        for c in m["columns"])
    value["membership"] = CharacterLaborCProducerMembershipV1(**m)
    result = CharacterLaborAccountingBasisV1(**value)
    if plain_v1(result) != raw:
        raise ValueError("labor accounting basis is not its exact canonical wire")
    return result


def _point(db, table, columns, key_columns, key):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    return _producer_original_point_v3(db, table=table, columns=columns,
        key_columns=key_columns, key=key, legacy_reader=lambda: db.execute(
            "SELECT " + ",".join(columns) + " FROM " + table + " WHERE " +
            " AND ".join(k + "=?" for k in key_columns), key).fetchone())


def _decoded(encoded):
    from .domain_background_read_v3 import background_json_loads_v3, background_json_matches_v3
    from .current_method_learning_read_v3 import MethodJSONColumnV3
    value = background_json_loads_v3(encoded)
    matches = encoded.matches_v3(value) if type(encoded) is MethodJSONColumnV3 else background_json_matches_v3(encoded, value)
    if not matches:
        raise ValueError("labor accounting source column is not complete canonical JSON")
    return value


def _signed(db, namespace, kind, ref, issuer):
    from .d11_life_preparation_v1 import SIGN_KIND as LIFE_SIGN_KIND
    row = _point(db, TABLE, ("producing_operation_id", "payload_json", "payload_digest", "signature"),
        ("bot", "persona", "kind", "original_ref"), (*namespace.as_tuple, kind, ref))
    if row is None:
        return None
    raw = _decoded(row[1])
    if canonical_digest(raw) != row[2]:
        raise ValueError("labor accounting source payload commitment changed")
    issuer._signer.verify(SIGN_KIND if kind == KIND else LIFE_SIGN_KIND,
        canonical_serialize((namespace, kind, ref, row[2])), row[3])
    return raw, row[0], row[2]


def _require_accounting(basis, accounting):
    b = accounting.binding
    if ((b.namespace, b.authority_namespace, b.authority_id, b.installation_id, b.manifest_digest,
            b.execution_id, b.effect_id, b.digest, b.prepare_operation_id, b.prepared_original_ref)
                != (basis.namespace, basis.authority_namespace, basis.authority_id, basis.installation_id,
                    basis.manifest_digest, basis.execution_id, basis.effect_id, basis.binding_digest,
                    basis.prepare_operation_id, basis.prepared_ref)
            or accounting.accounting_original_ref != basis.accounting_ref
            or accounting.prepared_digest != basis.prepared_digest
            or canonical_digest(plain_v1(accounting)) != basis.accounting_digest
            or (b.activity_id, b.clock_original_digest) !=
                (basis.membership.activity_id, basis.clock_original_digest)):
        raise ValueError("labor basis differs from the independently signed content-free CPU accounting original")


def validate_character_labor_accounting_basis_row_v1(columns, row, *, namespace, issuer):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS) or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("exact actual Life accounting basis row and installed issuer required")
    if tuple(row[:2]) != namespace.as_tuple or row[2] != KIND:
        raise ValueError("labor accounting basis row belongs to another namespace or kind")
    raw = _decoded(row[5])
    value = character_labor_accounting_basis_from_wire_v1(raw)
    digest = canonical_digest(raw)
    if (row[3] != "character-labor-accounting:" + value.execution_id
            or row[4] != value.prepare_operation_id or value.namespace != namespace or row[6] != digest):
        raise ValueError("labor accounting basis row locator or producer changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, KIND, row[3], digest)), row[7])
    return value


def read_character_labor_accounting_basis_v1(db, *, namespace, execution_id, issuer):
    from .d10_offline_tick_execution_v1 import _decode_json
    from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
    ref = "character-labor-accounting:" + execution_id
    row = _point(db, TABLE, COLUMNS, ("bot", "persona", "kind", "original_ref"),
        (*namespace.as_tuple, KIND, ref))
    if row is None:
        return None
    basis = validate_character_labor_accounting_basis_row_v1(COLUMNS, row, namespace=namespace, issuer=issuer)
    saved = _signed(db, namespace, "accounting_prepared", basis.accounting_ref, issuer)
    if saved is None or saved[1:] != (basis.prepare_operation_id, basis.accounting_digest):
        raise ValueError("labor basis has no authentic retained CPU accounting original")
    accounting = _decode_json(canonical_serialize(saved[0]), D11LifeAccountingPreparedV1)
    _require_accounting(basis, accounting)
    return basis


def _membership(db, *, frame, metadata, accounting, receipt):
    from .d04_root_original_store_v1 import _receipt
    ns, b = metadata.namespace, metadata.binding
    if (type(receipt) is not CommitReceipt or receipt.status != "committed"
            or _receipt(db, ns, b.prepare_operation_id) != receipt
            or frame.envelope.identity.operation_id != b.prepare_operation_id
            or receipt.activity_id != b.activity_id or receipt.effect_id != b.effect_id
            or metadata.receipt_digest != canonical_digest(receipt)
            or len(receipt.invalidated_epochs) != 1
            or receipt.invalidated_epochs[0].revision != metadata.graph_epoch):
        raise ValueError("labor accounting requires the actual complete same-C receipt")
    event = _point(db, "graph_events", ("digest", "reads", "revisions", "invalidated", "epoch_revision"),
        ("bot", "persona", "session", "event_id"), (*ns.as_tuple, b.activity_id, b.prepare_operation_id))
    if event is None or event[4] != metadata.graph_epoch:
        raise ValueError("labor C event header is absent or changed")
    arrays = tuple(_decoded(v) for v in event[1:4])
    reads = [[v.key.token, v.revision] for v in receipt.read_versions]
    writes = [[v.key.token, v.revision] for v in receipt.write_versions]
    # Event encoding is an ordered canonical array; compare exact membership,
    # and keep only its authenticated complete-column commitments afterward.
    if arrays[0] != reads or arrays[1] != writes:
        raise ValueError("labor C event lost its actual receipt read/write/namespace membership")
    expected = {v.key.token: v.revision for v in frame.envelope.version_guard.read_versions}
    if (len(expected) != len(reads) or dict(arrays[0]) != expected
            or any(expected.get(v.key.token) != v.revision for v in frame.snapshot.versions)):
        raise ValueError("labor C receipt differs from the actual complete pre-C frame")
    invalidated = arrays[2]
    if type(invalidated) is not list or len({tuple(v) for v in invalidated}) != len(invalidated):
        raise ValueError("labor C invalidation stream is not its actual unique version array")
    for item in invalidated:
        if (type(item) is not list or len(item) != 2 or type(item[1]) is not int or item[1] < 1
                or NamespaceId.from_key(AtomKey.from_token(item[0])) != ns):
            raise ValueError("labor C invalidation stream changed namespace or revision")
        h = _point(db, "graph_history", ("valid", "event_bot", "event_persona", "event_session", "event_id"),
            ("token", "revision"), tuple(item))
        if h != (0, *ns.as_tuple, b.activity_id, b.prepare_operation_id):
            raise ValueError("labor C invalidation is not an actual same-event history member")
    columns = tuple(CharacterLaborColumnCommitmentV1(name,
        sha256(canonical_serialize(raw).encode("utf-8")).hexdigest(),
        len(canonical_serialize(raw).encode("utf-8")))
        for name, raw in zip(("reads", "revisions", "invalidated"), arrays))
    key = AtomKey(Owner("activity", *ns.as_tuple, b.activity_id), "runtime.job", b.job_id)
    versions = tuple(v for v in receipt.write_versions if v.key == key)
    if len(versions) != 1 or versions[0].revision != metadata.job_projection_revision:
        raise ValueError("labor C receipt does not contain its actual unique prepared job")
    history = _point(db, "graph_history", ("value", "valid", "event_bot", "event_persona", "event_session", "event_id"),
        ("token", "revision"), (key.token, versions[0].revision))
    if history is None or history[1:] != (1, *ns.as_tuple, b.activity_id, b.prepare_operation_id):
        raise ValueError("labor prepared job has no actual same-C valid history")
    job = _decoded(history[0])
    if canonical_serialize(job) != metadata.job_projection_json:
        raise ValueError("labor prepared job differs from its authenticated C metadata")
    return CharacterLaborCProducerMembershipV1(ns, b.prepare_operation_id, b.activity_id, b.effect_id,
        metadata.prepared_ref, metadata.prepared_digest, accounting.accounting_original_ref,
        canonical_digest(plain_v1(accounting)), canonical_digest(receipt), receipt.operation_digest,
        receipt.commit_seq, event[0], metadata.graph_epoch, key.token, versions[0].revision,
        sha256(canonical_serialize(job).encode("utf-8")).hexdigest(), columns)


def record_character_labor_accounting_basis_after_cas_v1(db, *, frame, execution_id, receipt, issuer):
    from .d11_character_work_segment_v1 import (
        PREPARED_METADATA_KIND, ADMISSION_KIND, character_labor_prepared_metadata_from_wire_v1,
        character_labor_admission_from_wire_v1, require_character_labor_body_preparation_v1)
    from .d10_offline_tick_execution_v1 import _decode_json
    from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1, life_accounting_original_ref_v1
    from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOriginalRefV1
    from .d11_life_preparation_v1 import SIGN_KIND as LIFE_SIGN_KIND
    if not db.in_transaction or type(frame) is not CurrentOperationFrameV1 or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("labor basis is issued only inside the actual C after-CAS transaction")
    ns = frame.envelope.authority.namespace
    saved = _signed(db, ns, PREPARED_METADATA_KIND, "character-labor-prepared-metadata:" + execution_id, issuer)
    if saved is None:
        raise ValueError("labor accounting basis requires the actual signed C metadata")
    metadata = character_labor_prepared_metadata_from_wire_v1(saved[0])
    b = metadata.binding
    if metadata.namespace != ns or b.execution_id != execution_id or saved[1] != b.prepare_operation_id:
        raise ValueError("labor accounting metadata belongs to another C producer")
    header = _point(db, TABLE, ("producing_operation_id", "payload_digest", "signature"),
        ("bot", "persona", "kind", "original_ref"), (*ns.as_tuple, "character_labor_prepared_v1", metadata.prepared_ref))
    if header is None or header[:2] != (b.prepare_operation_id, metadata.prepared_digest):
        raise ValueError("labor accounting has no actual signed final Prepared header")
    issuer._signer.verify(LIFE_SIGN_KIND, canonical_serialize((ns, "character_labor_prepared_v1",
        metadata.prepared_ref, metadata.prepared_digest)), header[2])
    a = _signed(db, ns, ADMISSION_KIND, metadata.labor_admission_ref, issuer)
    if (a is None or a[1:] != (b.prepare_operation_id, metadata.labor_admission_digest)
            or set(a[0]) != {"schema", "admission", "body_preparation_digest", "receipt_digest"}
            or a[0]["schema"] != "d11.character-labor-admission-original.v1"
            or a[0]["receipt_digest"] != metadata.receipt_digest):
        raise ValueError("labor accounting has no actual same-C signed admission")
    admission = character_labor_admission_from_wire_v1(a[0]["admission"])
    bref = metadata.plan.labor_body_preparation_original
    bop = bref.original_ref.removeprefix("character-labor-body:")
    body = require_character_labor_body_preparation_v1(db, namespace=ns, operation_id=bop, issuer=issuer)
    body_digest = canonical_digest(plain_v1(body))
    if (body_digest != bref.original_digest or body_digest != admission.body_preparation_digest
            or body_digest != a[0]["body_preparation_digest"] or admission.binding_digest != b.digest
            or admission.execution_id != execution_id or admission.prepared_original_ref != metadata.prepared_ref
            or admission.admission_operation_id != b.prepare_operation_id
            or admission.admission_ref != metadata.labor_admission_ref
            or admission.reservation_ref != body.reservation_ref
            or admission.reservation_digest != body.reservation_digest
            or admission.policy_digest != canonical_digest(plain_v1(body.policy))
            or admission.quote_digest != canonical_digest(body.quote)):
        raise ValueError("labor accounting differs from its authenticated B/admission projection")
    old = _signed(db, ns, "accounting_prepared", life_accounting_original_ref_v1(b), issuer)
    if old is None or old[1] != b.prepare_operation_id:
        raise ValueError("labor accounting requires the actual same-C CPU accounting original")
    accounting = _decode_json(canonical_serialize(old[0]), D11LifeAccountingPreparedV1)
    if accounting.binding != b or accounting.prepared_digest != metadata.prepared_digest:
        raise ValueError("labor accounting projection differs from its actual final Prepared")
    read_versions = {v.key.token: v.revision for v in receipt.read_versions}
    if (read_versions.get(body.reservation_ref) != body.reservation_revision
            or read_versions.get(body.settlement_ref) != 0):
        raise ValueError("labor accounting lost C's initial actual reservation/settlement boundary")
    mapping = _mapping_from_dict(json.loads(metadata.clock_mapping_json))
    if (canonical_digest(json.loads(metadata.clock_original_json)) != body.quote.clock_original_digest
            or json.loads(body.clock_mapping_json) != json.loads(metadata.clock_mapping_json)):
        raise ValueError("labor accounting differs from the actual authenticated B/C clock")
    membership = _membership(db, frame=frame, metadata=metadata, accounting=accounting, receipt=receipt)
    basis = CharacterLaborAccountingBasisV1(ns, b.authority_namespace, b.authority_id, b.installation_id,
        b.manifest_digest, execution_id, b.effect_id, b.digest, b.prepare_operation_id,
        metadata.prepared_ref, metadata.prepared_digest, accounting.accounting_original_ref, old[2],
        bref.original_ref, body_digest, body.body_prepare_operation_id, body.receipt_digest,
        metadata.labor_admission_ref, metadata.labor_admission_digest,
        body.recipe_ref, body.recipe_revision, body.recipe_digest, body.policy,
        canonical_digest(plain_v1(body.policy)), body.quote, canonical_digest(body.quote),
        body.reservation_ref, body.reservation_revision, body.reservation_digest,
        body.settlement_ref, 0, None, canonical_serialize(_mapping_dict(mapping)),
        body.quote.clock_original_digest, canonical_digest(receipt), membership)
    _require_accounting(basis, accounting)
    ref = "character-labor-accounting:" + execution_id
    wire, digest = canonical_serialize(plain_v1(basis)), canonical_digest(plain_v1(basis))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((ns, KIND, ref, digest)))
    expected = (b.prepare_operation_id, wire, digest, signature)
    prior = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*ns.as_tuple, KIND, ref)).fetchone()
    if prior is not None and prior != expected:
        raise ValueError("immutable labor accounting basis replay changed")
    if prior is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*ns.as_tuple, KIND, ref, *expected))
    return ProductionOriginalRefV1("d11.life_" + KIND, ref, digest)


def read_character_labor_accounting_prepared_v1(db, *, binding, issuer, resource_issuer):
    """Historical originals only; the verified C attestation replaces no grant."""
    from .d10_offline_tick_execution_v1 import _decode_json
    from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
    from .issuers import BudgetLeaseGrant
    basis = read_character_labor_accounting_basis_v1(db, namespace=binding.namespace,
        execution_id=binding.execution_id, issuer=issuer)
    if basis is None:
        return None
    saved = _signed(db, binding.namespace, "accounting_prepared", basis.accounting_ref, issuer)
    value = _decode_json(canonical_serialize(saved[0]), D11LifeAccountingPreparedV1)
    if value.binding != binding:
        raise ValueError("labor accounting basis belongs to another actual Life execution")
    if canonical_serialize(plain_v1(resource_issuer.original_signed_quote(
            db, binding.quote_id, binding.quote_version))) != value.quote_json:
        raise ValueError("labor accounting original signed resource quote changed")
    grant = _decode_json(value.signed_grant_json, BudgetLeaseGrant)
    actual, signature = issuer.signed_budget_grant_at_version(db, grant.lease_id, grant.version)
    if actual != grant or signature != value.signed_grant_signature:
        raise ValueError("labor accounting original signed grant changed")
    reserve = _point(db, "runtime_budget_operations", ("receipt_json",),
        ("bot_id", "persona_id", "operation_id", "phase"),
        (*binding.namespace.as_tuple, binding.reservation_operation_id, "reserve"))
    reservation = _point(db, "runtime_budget_reservations", ("digest", "ceiling_json"),
        ("lease_id", "operation_id"), (binding.parent_budget_lease_ref, binding.reservation_operation_id))
    if (reserve is None or _decoded(reserve[0]) != json.loads(value.reserve_receipt_json)
            or reservation is None or reservation[0] != binding.reservation_digest
            or _decoded(reservation[1]) != {"thread_cpu_ms": binding.cpu_ceiling_ms}):
        raise ValueError("labor accounting retained reserve differs from its authentic original")
    return basis, value

