"""Installed, content-free authority for one adopted natural roster.

This fixed metadata observer has no Owner business frame and can grant only
one D09 continuation-fact CAS. It cannot create an intent, expense or effect.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass, replace
import json
import hashlib
import hmac
import secrets
from pathlib import Path
import sqlite3

from ..domains.d09.natural_disposition_v1 import (
    NaturalBatchDispositionV1, natural_disposition_from_wire_v1,
    natural_disposition_key_v1,
)
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime.natural_same_batch_history_v3 import read_natural_roster_head_v1
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, to_wire, from_wire
from .v2_execution_bridge import AuthorityV2ExecutionBridge


class NaturalDispositionProjectionUnavailableV1(AuthorityUnavailable):
    """The optional no-content bubble projection has no adopted original proof."""


ORIGINAL_KINDS = frozenset({"roster_prepared","roster_committed","maintenance_prepared","maintenance_committed","rejected_no_commit"})
ORIGINAL_TABLE = "authority_natural_disposition_originals_v1"
ORIGINAL_COLUMNS = ("authority_namespace", "installation_id", "kind", "operation_id", "original_ref", "payload_json", "payload_digest", "signature")
ORIGINAL_DDL = "CREATE TABLE IF NOT EXISTS "+ORIGINAL_TABLE+"(authority_namespace TEXT NOT NULL,installation_id TEXT NOT NULL,"+    "kind TEXT NOT NULL,operation_id TEXT NOT NULL,original_ref TEXT NOT NULL UNIQUE,payload_json TEXT NOT NULL,"+    "payload_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(authority_namespace,installation_id,kind,operation_id))"
ORIGINAL_TRIGGER_DDLS = tuple("CREATE TRIGGER IF NOT EXISTS "+ORIGINAL_TABLE+"_no_"+action.lower()+" BEFORE "+action+" ON "+ORIGINAL_TABLE+
    " BEGIN SELECT RAISE(ABORT,'immutable natural disposition Core original'); END" for action in ("UPDATE", "DELETE"))
SIGNING_KEY_PREFIX = "natural-disposition-signing-key-v1:"


def validate_core_original_payload_v1(kind, payload):
    """Closed original shapes: no text, caller-chosen authority, or generic writes."""
    common = {"roster_ref", "expected_next_value", "next_payload_digest", "prior_revision", "graph_revision", "graph_epoch", "requirements", "storage_commitment", "permit"}
    shapes = {
        "roster_prepared": common | {"paid_request_digest", "generation_observation_digest", "review_observation_digest", "read_versions"},
        "maintenance_prepared": common | {"plan"},
        "roster_committed": {"prepared_original_ref", "prepared_original_digest", "roster_ref", "next_payload_digest", "next_revision", "graph_receipt_digest", "post_graph_epoch", "permit", "storage_commitment"},
        "maintenance_committed": {"prepared_original_ref", "prepared_original_digest", "roster_ref", "next_payload_digest", "next_revision", "graph_receipt_digest", "post_graph_epoch", "permit", "storage_commitment"},
        "rejected_no_commit": {"prepared_original_ref", "prepared_original_digest", "permit", "storage_commitment", "state"},
    }
    if kind=="rejected_no_commit" and type(payload) is dict and payload.get("state")=="proven_no_preparation_no_graph_commit":
        shapes[kind]=shapes[kind]|{"scope"}
    if kind not in shapes or type(payload) is not dict or set(payload) != shapes[kind]:
        raise ValueError("natural Core original closed payload shape differs")
    for field, value in payload.items():
        if (field.endswith("_digest") or field == "storage_commitment") and not (kind=="rejected_no_commit" and payload.get("state")=="proven_no_preparation_no_graph_commit" and field=="prepared_original_digest"):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("natural Core original exact digest is invalid")
    permit = from_wire(payload["permit"])
    if type(permit) is not FencePermitV2 or permit.operation != "write":
        raise ValueError("natural Core original needs its actual write permit")
    if kind.endswith("_prepared"):
        expected = natural_disposition_from_wire_v1(payload["expected_next_value"])
        requirements = dict(payload["requirements"])
        requirements["namespace"] = NamespaceId(**requirements["namespace"])
        requirements = SnapshotRequirementsV2(**requirements)
        if (payload["roster_ref"] != natural_disposition_key_v1(expected).token
                or payload["next_payload_digest"] != canonical_digest(expected.to_wire())
                or type(payload["prior_revision"]) is not int or payload["prior_revision"] != expected.revision - 1
                or requirements.namespace != expected.namespace
                or requirements.authority_namespace != permit.namespace
                or requirements.activation_generation != permit.generation
                or any(type(payload[field]) is not int or payload[field] < 0 for field in ("graph_revision", "graph_epoch"))):
            raise ValueError("natural Core preparation exact scope/revision differs")
        if kind == "roster_prepared":
            if (expected.revision != 1 or expected.authority_original_ref != expected.birth_original_ref
                    or any(c.continuation_state != "ready" for c in expected.children)
                    or type(payload["read_versions"]) is not list or not 1 <= len(payload["read_versions"]) <= 1025):
                raise ValueError("natural Core birth finite complete roster differs")
            versions = tuple(GraphVersion(AtomKey.from_token(v["ref"]), v["revision"]) for v in payload["read_versions"])
            if any(NamespaceId.from_key(v.key) != expected.namespace for v in versions):
                raise ValueError("natural Core birth crossed its actual read namespace")
        else:
            plan = plan_from_wire_v1(payload["plan"])
            if (plan.next_value != expected or plan.request.operation_id != permit.operation_id
                    or plan.anchor != permit.pinned_anchor or plan.graph_revision != payload["graph_revision"]
                    or plan.graph_epoch != payload["graph_epoch"] or plan.storage_commitment != payload["storage_commitment"]):
                raise ValueError("natural Core maintenance changed its exact named plan")
    elif kind.endswith("_committed"):
        if (type(payload["next_revision"]) is not int or payload["next_revision"] < 1
                or type(payload["post_graph_epoch"]) is not int or payload["post_graph_epoch"] < 1
                or AtomKey.from_token(payload["roster_ref"]).type_name != "d09.natural_batch_disposition.v1"):
            raise ValueError("natural Core confirmation actual revision differs")
    elif payload["state"]=="proven_no_preparation_no_graph_commit":
        scope=unprepared_closure_from_wire_v1(payload["scope"])
        if payload["prepared_original_ref"] is not None or payload["prepared_original_digest"] is not None:
            raise ValueError("unprepared refusal cannot invent a prepared original")
        require_unprepared_family_permit_v1(scope,permit)
        if scope.storage_commitment!=payload["storage_commitment"]:
            raise ValueError("unprepared refusal storage observation commitment differs")
    elif payload["state"] != "proven_no_graph_commit":
        raise ValueError("natural Core refusal cannot assert an unknown Graph outcome")
    return payload


def natural_disposition_original_ref_v1(namespace, installation_id, parent_original_id, kind, operation_id):
    return "natural-disposition-original:"+canonical_digest((namespace,installation_id,parent_original_id,kind,operation_id))[:48]


@dataclass(frozen=True, slots=True)
class NaturalDispositionCoreOriginalV1:
    authority_namespace: str
    installation_id: str
    parent_original_id: str | None
    kind: str
    operation_id: str
    original_ref: str
    payload: dict
    payload_digest: str
    signature: str
    schema: str = "sylanne.natural-disposition-core-original.v1"

    def to_wire(self):
        return asdict(self)

    @property
    def digest(self):
        return canonical_digest(self.to_wire())


def core_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw)!=set(NaturalDispositionCoreOriginalV1.__dataclass_fields__):
        raise ValueError("exact natural disposition Core original required")
    value=NaturalDispositionCoreOriginalV1(**raw)
    if (value.schema!="sylanne.natural-disposition-core-original.v1" or value.kind not in ORIGINAL_KINDS
            or value.original_ref!=natural_disposition_original_ref_v1(value.authority_namespace,value.installation_id,
                value.parent_original_id,value.kind,value.operation_id)
            or type(value.payload) is not dict or canonical_digest(value.payload)!=value.payload_digest
            or type(value.signature) is not str or len(value.signature)!=64):
        raise ValueError("natural disposition Core original identity/payload differs")
    validate_core_original_payload_v1(value.kind, value.payload)
    if value.kind.endswith("_prepared"):
        expected=natural_disposition_from_wire_v1(value.payload["expected_next_value"])
        if (expected.parent_original_id!=value.parent_original_id or expected.installation_id!=value.installation_id
                or expected.authority_original_ref!=value.original_ref
                or value.kind=="roster_prepared" and (expected.birth_original_ref!=value.original_ref or value.operation_id!=expected.creation_operation_id)):
            raise ValueError("natural Core prepared original crossed its exact parent/installation/roster identity")
    elif value.kind=="rejected_no_commit" and value.payload["state"]=="proven_no_preparation_no_graph_commit":
        permit=from_wire(value.payload["permit"])
        scope=unprepared_closure_from_wire_v1(value.payload["scope"])
        if value.parent_original_id is not None or value.operation_id!=permit.operation_id or value.installation_id!=scope.installation_id:
            raise ValueError("unprepared refusal cannot claim an unverified parent identity")
    else:
        kinds=("roster_prepared","maintenance_prepared") if value.kind=="rejected_no_commit" else (("roster_prepared",) if value.kind=="roster_committed" else ("maintenance_prepared",))
        if value.payload["prepared_original_ref"] not in {natural_disposition_original_ref_v1(value.authority_namespace,value.installation_id,
                value.parent_original_id,kind,value.operation_id) for kind in kinds}:
            raise ValueError("natural Core terminal original crossed its exact prepared lineage")
    return value


@dataclass(frozen=True, slots=True)
class NaturalUnpreparedWriteClosureRequestV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    graph_revision: int
    graph_epoch: int
    graph_incarnation: str
    storage_commitment: str
    family: str
    schema: str = "sylanne.natural-unprepared-write-closure.v1"

    def to_wire(self):
        return asdict(self)


def unprepared_closure_from_wire_v1(raw):
    if type(raw) is not dict or set(raw)!=set(NaturalUnpreparedWriteClosureRequestV1.__dataclass_fields__):
        raise ValueError("exact named natural unprepared closure required")
    data=dict(raw);data["namespace"]=NamespaceId(**data["namespace"])
    value=NaturalUnpreparedWriteClosureRequestV1(**data)
    if (value.schema!="sylanne.natural-unprepared-write-closure.v1" or value.family not in {"roster","maintenance"}
            or any(type(v) is not str or not 1<=len(v)<=256 for v in (value.installation_id,value.operation_id,value.graph_incarnation))
            or any(type(v) is not int or v<0 for v in (value.graph_revision,value.graph_epoch))
            or type(value.storage_commitment) is not str or len(value.storage_commitment)!=64
            or any(c not in "0123456789abcdef" for c in value.storage_commitment)):
        raise ValueError("natural unprepared closure installed metadata scope differs")
    return value


def require_unprepared_family_permit_v1(request,permit):
    expected=("natural-final:"+canonical_digest({"namespace":request.namespace.as_tuple,"operation_id":request.operation_id})[:48]
        if request.family=="roster" else request.operation_id)
    if (type(permit) is not FencePermitV2 or permit.operation!="write" or permit.operation_id!=expected
            or request.family=="maintenance" and not request.operation_id.startswith("natural-disposition:")):
        raise ValueError("unprepared closure uses another actual family operation permit")


@dataclass(frozen=True, slots=True)
class NaturalGraphIdentityV1:
    namespace: NamespaceId
    installation_id: str
    graph_path: str
    graph_device: int
    graph_file_id: int
    graph_incarnation: str
    storage_commitment: str
    schema: str = "sylanne.natural-current-graph-identity.v1"

    def to_wire(self):
        return asdict(self)


def natural_graph_identity_from_wire_v1(raw):
    if type(raw) is not dict or set(raw)!=set(NaturalGraphIdentityV1.__dataclass_fields__):
        raise ValueError("exact current installed natural Graph identity required")
    data=dict(raw);data["namespace"]=NamespaceId(**data["namespace"])
    value=NaturalGraphIdentityV1(**data)
    if (value.schema!="sylanne.natural-current-graph-identity.v1" or not Path(value.graph_path).is_absolute()
            or type(value.graph_device) is not int or value.graph_device<0
            or type(value.graph_file_id) is not int or value.graph_file_id<1
            or any(type(v) is not str or not 1<=len(v)<=256 for v in (value.installation_id,value.graph_incarnation))
            or type(value.storage_commitment) is not str or len(value.storage_commitment)!=64
            or any(c not in "0123456789abcdef" for c in value.storage_commitment)):
        raise ValueError("natural Graph identity current installed scope differs")
    return value


def validate_original_terminal_fence_in_tx_v1(db, original):
    """Read the actual finished same-Core fence of one closed refusal variant."""
    from .v2_fence_store import AuthorityV2FenceStore
    if original.kind!="rejected_no_commit":
        raise ValueError("natural terminal fence helper accepts only the closed refusal family")
    permit=from_wire(original.payload["permit"])
    row=AuthorityV2FenceStore._row(db,permit.operation_id)
    if original.payload["state"]=="proven_no_preparation_no_graph_commit":
        digest="sha256:"+canonical_digest(("natural_unprepared_closed_refusal.v1",permit.operation_id,permit.token,
            canonical_digest(original.payload["scope"])))
    else:
        digest="sha256:"+canonical_digest(("natural_disposition_closed_refusal.v1",original.payload["prepared_original_ref"],
            original.payload["prepared_original_digest"],permit.token,original.payload["storage_commitment"]))
    if (row is None or AuthorityV2FenceStore._permit(row)!=permit or row[6]!="finished" or row[10] is not None
            or row[8:10]!=("reject:"+permit.operation_id,digest)):
        raise AuthorityUnavailable("natural refusal has no exact actual finished Core fence receipt")
    return True


class NaturalDispositionCoreOriginalStoreV1:
    """Closed immutable evidence family in the actual protected Core database."""
    def __init__(self, owner):
        self.owner=owner
        key_name=SIGNING_KEY_PREFIX+canonical_digest((owner.namespace,owner.installation_id))
        with owner.core._tx() as db:
            db.execute(ORIGINAL_DDL)
            for ddl in ORIGINAL_TRIGGER_DDLS:
                db.execute(ddl)
            row=db.execute("SELECT value FROM authority_meta WHERE key=?",(key_name,)).fetchone()
            if row is None:
                secret=secrets.token_bytes(32)
                db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)",(key_name,secret.hex()))
            else:
                secret=bytes.fromhex(row[0])
            if len(secret)!=32:
                raise AuthorityUnavailable("installed natural disposition signing material is invalid")
        self._key=secret

    def pending_maintenance(self, parent_original_id):
        with self.owner.core._tx() as db:
            rows=db.execute("SELECT p.payload_json,p.payload_digest,p.signature FROM "+ORIGINAL_TABLE+" p WHERE p.authority_namespace=? AND p.installation_id=? "
                "AND p.kind='maintenance_prepared' AND json_extract(p.payload_json,'$.parent_original_id')=? AND NOT EXISTS(SELECT 1 FROM "+ORIGINAL_TABLE+
                " c WHERE c.authority_namespace=p.authority_namespace AND c.installation_id=p.installation_id AND c.operation_id=p.operation_id "
                "AND c.kind IN ('maintenance_committed','rejected_no_commit')) ORDER BY p.rowid LIMIT 2",
                (self.owner.namespace,self.owner.installation_id,parent_original_id)).fetchall()
            if len(rows)>1:
                raise AuthorityUnavailable("natural metadata has more than one unresolved original operation")
            return None if not rows else self._decode(rows[0])

    def latest_committed(self, parent_original_id):
        with self.owner.core._tx() as db:
            rows=db.execute("SELECT payload_json,payload_digest,signature FROM "+ORIGINAL_TABLE+
                " WHERE authority_namespace=? AND installation_id=? AND kind IN ('roster_committed','maintenance_committed') "
                "AND json_extract(payload_json,'$.parent_original_id')=? ORDER BY json_extract(payload_json,'$.payload.next_revision') DESC LIMIT 2",
                (self.owner.namespace,self.owner.installation_id,parent_original_id)).fetchall()
            values=tuple(self._decode(row) for row in rows)
            if len(values)==2 and values[0].payload["next_revision"]==values[1].payload["next_revision"]:
                raise NaturalDispositionProjectionUnavailableV1("natural disposition independent committed revision is ambiguous")
            return None if not values else values[0]

    def _sign(self, material):
        return hmac.new(self._key,b"sylanne.natural-disposition-original.v1\0"+canonical_serialize(material).encode("utf-8"),hashlib.sha256).hexdigest()

    def _decode(self, row):
        try:
            value=core_original_from_wire_v1(json.loads(row[0]))
        except (ValueError,TypeError) as exc:
            raise NaturalDispositionProjectionUnavailableV1("natural disposition stored original proof cannot be decoded") from exc
        if len(row)!=3 or row[1:]!=(value.payload_digest,value.signature):
            raise NaturalDispositionProjectionUnavailableV1("natural disposition stored original columns differ")
        material={k:v for k,v in value.to_wire().items() if k!="signature"}
        if (value.authority_namespace,value.installation_id)!=(self.owner.namespace,self.owner.installation_id) or not hmac.compare_digest(value.signature,self._sign(material)):
            raise NaturalDispositionProjectionUnavailableV1("natural disposition Core original has no installed private signature")
        return value

    def read(self, original_ref):
        with self.owner.core._tx() as db:
            row=db.execute("SELECT payload_json,payload_digest,signature FROM "+ORIGINAL_TABLE+" WHERE authority_namespace=? AND installation_id=? AND original_ref=?",
                (self.owner.namespace,self.owner.installation_id,original_ref)).fetchone()
            return None if row is None else self._decode(row)

    def append_in_tx(self, db, *, parent_original_id, kind, operation_id, payload):
        if db is not self.owner.core._db or not db.in_transaction or kind not in ORIGINAL_KINDS:
            raise AuthorityUnavailable("natural disposition original needs its exact same-Core closed transaction")
        payload=json.loads(canonical_serialize(payload))
        validate_core_original_payload_v1(kind,payload)
        material=dict(authority_namespace=self.owner.namespace,installation_id=self.owner.installation_id,parent_original_id=parent_original_id,
            kind=kind,operation_id=operation_id,original_ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,parent_original_id,kind,operation_id),
            payload=payload,payload_digest=canonical_digest(payload),schema="sylanne.natural-disposition-core-original.v1")
        value=NaturalDispositionCoreOriginalV1(**material,signature=self._sign(material))
        old=db.execute("SELECT payload_json,payload_digest,signature FROM "+ORIGINAL_TABLE+" WHERE authority_namespace=? AND installation_id=? AND kind=? AND operation_id=?",
            (self.owner.namespace,self.owner.installation_id,kind,operation_id)).fetchone()
        if old is not None:
            actual=self._decode(old)
            if actual!=value:
                raise AuthorityUnavailable("natural disposition immutable original replay changed")
            return actual
        db.execute("INSERT INTO "+ORIGINAL_TABLE+" VALUES(?,?,?,?,?,?,?,?)",(self.owner.namespace,self.owner.installation_id,kind,operation_id,
            value.original_ref,canonical_serialize(value.to_wire()),value.payload_digest,value.signature))
        return value


@dataclass(frozen=True, slots=True)
class NaturalDispositionMaintenanceRequestV1:
    namespace: NamespaceId
    installation_id: str
    parent_original_id: str
    roster_ref: str
    expected_revision: int
    operation_id: str
    next_payload_digest: str
    schema: str = "sylanne.natural-disposition-maintenance-request.v1"

    def to_wire(self):
        return asdict(self)


def request_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(NaturalDispositionMaintenanceRequestV1.__dataclass_fields__):
        raise ValueError("exact natural disposition maintenance request required")
    values = dict(raw); values["namespace"] = NamespaceId(**values["namespace"])
    value = NaturalDispositionMaintenanceRequestV1(**values)
    if (value.schema != "sylanne.natural-disposition-maintenance-request.v1"
            or type(value.expected_revision) is not int or value.expected_revision < 1
            or AtomKey.from_token(value.roster_ref).type_name != "d09.natural_batch_disposition.v1"
            or NamespaceId.from_key(AtomKey.from_token(value.roster_ref)) != value.namespace
            or any(type(v) is not str or not 1 <= len(v) <= 192 for v in (value.installation_id,value.parent_original_id,value.operation_id))
            or type(value.next_payload_digest) is not str or len(value.next_payload_digest) != 64):
        raise ValueError("natural disposition maintenance request scope differs")
    return value


@dataclass(frozen=True, slots=True)
class NaturalDispositionMaintenancePlanV1:
    request: NaturalDispositionMaintenanceRequestV1
    anchor: RestoreAnchor
    requirements: SnapshotRequirementsV2
    graph_revision: int
    graph_epoch: int
    read_versions: tuple[GraphVersion, ...]
    next_value: NaturalBatchDispositionV1
    observed_at_utc: float | None
    observation_digest: str
    changed: bool
    storage_commitment: str
    schema: str = "sylanne.natural-disposition-maintenance-plan.v1"

    def to_wire(self):
        data = asdict(self)
        data["request"] = self.request.to_wire()
        data["next_value"] = self.next_value.to_wire()
        data["read_versions"] = [{"ref":v.key.token,"revision":v.revision} for v in self.read_versions]
        return data


def plan_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(NaturalDispositionMaintenancePlanV1.__dataclass_fields__):
        raise ValueError("exact natural disposition maintenance plan required")
    data = dict(raw); data["request"] = request_from_wire_v1(data["request"])
    data["next_value"] = natural_disposition_from_wire_v1(data["next_value"])
    data["anchor"] = RestoreAnchor(**data["anchor"])
    requirements = dict(data["requirements"]); requirements["namespace"] = NamespaceId(**requirements["namespace"])
    data["requirements"] = SnapshotRequirementsV2(**requirements)
    data["read_versions"] = tuple(GraphVersion(AtomKey.from_token(v["ref"]),v["revision"]) for v in data["read_versions"])
    value = NaturalDispositionMaintenancePlanV1(**data)
    if (value.schema != "sylanne.natural-disposition-maintenance-plan.v1"
            or value.request.namespace != value.next_value.namespace
            or value.request.installation_id != value.next_value.installation_id
            or value.request.roster_ref != natural_disposition_key_v1(value.next_value).token
            or value.request.next_payload_digest != canonical_digest(value.next_value.to_wire())
            or type(value.changed) is not bool or not 1 <= len(value.read_versions) <= 1025):
        raise ValueError("natural disposition plan identity/digest differs")
    return value


@dataclass(frozen=True, slots=True)
class NaturalDispositionMaintenanceObservedV1:
    plan: NaturalDispositionMaintenancePlanV1
    permit: FencePermitV2
    original: NaturalDispositionCoreOriginalV1
    schema: str = "sylanne.natural-disposition-maintenance-observed.v1"

    @property
    def digest(self):
        return canonical_digest(self.to_wire())

    def to_wire(self):
        return {"schema":self.schema,"plan":self.plan.to_wire(),"permit":to_wire(self.permit),"original":self.original.to_wire()}


def observed_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {"schema","plan","permit","original"}:
        raise ValueError("exact natural disposition private observation required")
    value = NaturalDispositionMaintenanceObservedV1(plan_from_wire_v1(raw["plan"]),from_wire(raw["permit"]),core_original_from_wire_v1(raw["original"]),raw["schema"])
    if (value.schema != "sylanne.natural-disposition-maintenance-observed.v1"
            or type(value.permit) is not FencePermitV2 or value.permit.operation != "write"
            or value.permit.operation_id != value.plan.request.operation_id
            or value.permit.pinned_anchor != value.plan.anchor
            or value.original.kind!="maintenance_prepared"
            or value.original.original_ref!=value.plan.next_value.authority_original_ref
            or value.original.payload["expected_next_value"]!=value.plan.next_value.to_wire()):
        raise ValueError("natural disposition observation does not bind its actual write fence")
    return value


@dataclass(frozen=True, slots=True)
class NaturalFeeMetadataV1:
    settlement_ref: str
    status: str
    currency: str
    actual: dict | None
    unconfirmed: dict


@dataclass(frozen=True, slots=True)
class NaturalBubbleMetadataV1:
    index: int
    operation_id: str
    effect_id: str
    actual_intent_ref: str | None
    admission_ref: str | None
    continuation_state: str
    reason_code: str | None
    authority_state: str
    observation_outcome: str | None
    observation_ref: str | None
    read_state: str
    fees: tuple[NaturalFeeMetadataV1, ...]


@dataclass(frozen=True, slots=True)
class NaturalBatchMetadataV1:
    schema: str
    parent_original_id: str
    roster_revision: int | None
    details_state: str
    parent_fees: tuple[NaturalFeeMetadataV1, ...]
    children: tuple[NaturalBubbleMetadataV1, ...]

    def to_wire(self):
        return json.loads(canonical_serialize(asdict(self)))


def validate_owner_natural_batch_metadata_v1(raw, parent_original_id):
    if type(raw) is not dict or set(raw)!=set(NaturalBatchMetadataV1.__dataclass_fields__):
        raise ValueError("exact Owner natural batch metadata required")
    if (raw["schema"]!="d12.natural-batch-metadata.v1" or raw["parent_original_id"]!=parent_original_id
            or raw["details_state"] not in {"adopted","manifest_not_adopted","bubble_details_unavailable"}
            or type(raw["children"]) is not list or len(raw["children"])>4
            or raw["details_state"]=="adopted" and (not raw["children"] or type(raw["roster_revision"]) is not int or raw["roster_revision"]<1)
            or raw["details_state"] in {"manifest_not_adopted","bubble_details_unavailable"} and (raw["children"] or raw["roster_revision"] is not None)
            or type(raw["parent_fees"]) is not list or len(raw["parent_fees"])>8):
        raise ValueError("Owner natural batch finite scope differs")
    from .v2_contract import _PLATFORM_OUTCOMES
    for index,child in enumerate(raw["children"]):
        if (type(child) is not dict or set(child)!=set(NaturalBubbleMetadataV1.__dataclass_fields__)
                or child["index"]!=index or child["continuation_state"] not in {"ready","held","cancelled","superseded"}
                or child["authority_state"] not in {"absent","unresolved","observed","unavailable"}
                or child["read_state"]!="unknown" or child["observation_outcome"] is not None and child["observation_outcome"] not in _PLATFORM_OUTCOMES
                or child["authority_state"]!="observed" and (child["observation_outcome"] is not None or child["observation_ref"] is not None)
                or (child["actual_intent_ref"] is None)!=(child["admission_ref"] is None)
                or type(child["fees"]) is not list or len(child["fees"])>4):
            raise ValueError("Owner natural child actual observation/intent metadata differs")
    fees=[*raw["parent_fees"],*(fee for child in raw["children"] for fee in child["fees"])]
    if len({fee["settlement_ref"] for fee in fees})!=len(fees):
        raise ValueError("Owner natural expense is counted twice")
    for fee in fees:
        if (type(fee) is not dict or set(fee)!=set(NaturalFeeMetadataV1.__dataclass_fields__)
                or fee["status"] not in {"settled","overrun","pending_confirmation","pending_overrun"}
                or type(fee["currency"]) is not str or len(fee["currency"])!=3):
            raise ValueError("Owner natural expense metadata differs")
        for amounts in (fee["actual"],fee["unconfirmed"]):
            if amounts is not None and (type(amounts) is not dict or len(amounts)>32
                    or any(type(v) is not int or v<0 for v in amounts.values())):
                raise ValueError("Owner natural expense amounts differ")


class InstalledNaturalDispositionMaintenanceServiceV1:
    def __init__(self, *, owner_reply_service, execution, clock_provider):
        from .owner_stop_reply_v1 import InstalledOwnerStopReplyServiceV1
        if (type(owner_reply_service) is not InstalledOwnerStopReplyServiceV1
                or type(execution) is not AuthorityV2ExecutionBridge
                or execution.core is not owner_reply_service.core
                or execution.fences is not owner_reply_service.fences.fences
                or execution.journal is not owner_reply_service.fences.execution
                or execution.deletion is not owner_reply_service.fences.deletion
                or execution.namespace != owner_reply_service.namespace):
            raise TypeError("natural metadata maintenance requires actual same-Core/namespace installed execution")
        self.owner = owner_reply_service
        self.execution = execution
        self.clock_provider = clock_provider
        self.originals = NaturalDispositionCoreOriginalStoreV1(owner_reply_service)

    def _require_committed_head_v1(self, head):
        """Graph is a projection: its whole payload must match two signed Core facts."""
        value=head[2]
        birth=self.originals.read(value.birth_original_ref)
        current=self.originals.read(value.authority_original_ref)
        if birth is None or birth.kind!="roster_prepared" or current is None or current.kind not in {"roster_prepared","maintenance_prepared"}:
            raise NaturalDispositionProjectionUnavailableV1("natural roster has no independent full Core birth/current original")
        for prepared in (birth,current):
            kind="roster_committed" if prepared.kind=="roster_prepared" else "maintenance_committed"
            ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,value.parent_original_id,kind,prepared.operation_id)
            committed=self.originals.read(ref)
            if (committed is None or committed.payload.get("prepared_original_digest")!=prepared.digest
                    or committed.payload.get("next_payload_digest")!=prepared.payload.get("next_payload_digest")):
                raise NaturalDispositionProjectionUnavailableV1("natural roster prepared fact is not an actual committed adoption")
        born=natural_disposition_from_wire_v1(birth.payload["expected_next_value"])
        immutable=("namespace","installation_id","parent_original_id","activity_id","generation_original_operation_id",
            "generation_original_digest","review_original_operation_id","review_original_digest","whole_output_digest",
            "creation_operation_id","identity_manifest_digest","dependency_refs","expires_at_utc","birth_original_ref")
        if any(getattr(born,field)!=getattr(value,field) for field in immutable):
            raise NaturalDispositionProjectionUnavailableV1("natural roster changed its independently proven birth identity")
        expected=natural_disposition_from_wire_v1(current.payload["expected_next_value"])
        latest=self.originals.latest_committed(value.parent_original_id)
        if (latest is None or latest.payload["next_revision"]!=head[1]
                or latest.payload["prepared_original_ref"]!=current.original_ref
                or latest.payload["next_payload_digest"]!=canonical_digest(value.to_wire())):
            raise NaturalDispositionProjectionUnavailableV1("natural roster is not its latest independent committed continuation revision")
        if expected!=value or current.payload["roster_ref"]!=head[0].token or expected.revision!=head[1]:
            raise NaturalDispositionProjectionUnavailableV1("natural roster differs from its exact independently signed adopted payload")
        return birth,current

    def prepare_roster_for_final_fence_v1(self, *, credential, subject, permit, paid_request, paid_service):
        """Independent C6/current Source read under the actual existing write fence."""
        self._paired(credential,subject)
        self.owner.fences._require_permit(credential=credential,subject=subject,permit=permit)
        self.owner.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        if type(permit) is not FencePermitV2 or permit.operation!="write" or paid_request.namespace!=self.owner.namespace_id:
            raise AuthorityUnavailable("normal natural roster preparation requires its actual first final write scope")
        generation,review=paid_service._generation,paid_service._review
        if generation._fences is not self.owner.fences or paid_service._graph._path!=self.owner.status_service._source_graphs[self.owner.installation_id]:
            raise AuthorityUnavailable("natural roster paid reader crossed actual installed Core/Graph")
        anchor=permit.pinned_anchor; now=paid_service._clock()
        gen_intent,gen_receipt,_=generation._read_original(paid_request.generation_content_request,anchor,content=False)
        review_intent,review_receipt,_=review._read_original(paid_request.review_output_request,anchor,content=False)
        original=paid_service._graph.read(paid_request,gen_intent,gen_receipt,review_intent,review_receipt,
            now_utc=now,credential=credential,subject=subject,fences=self.owner.fences,permit=permit,same_batch_prepared=None)
        if original is None:
            raise AuthorityUnavailable("natural roster actual current paid/Owner/Source qualification unavailable")
        second_gen,second_gen_receipt,gen_observation=generation._read_original(paid_request.generation_content_request,anchor,content=True)
        second_review,second_review_receipt,review_observation=review._read_original(paid_request.review_output_request,anchor,content=True)
        if (second_gen,second_gen_receipt,second_review,second_review_receipt)!=(gen_intent,gen_receipt,review_intent,review_receipt):
            raise AuthorityUnavailable("natural roster paid originals changed after current Owner/Source qualification")
        current,saved,generation_saved,generation_binding,binding,output,versions,scope=original
        from ..model_broker.natural_reply import parse_natural_reply_output_v2
        from ..model_broker.natural_review import parse_natural_reply_review_output_v1
        from ..domains.d09.natural_reply import mechanically_verify_natural_reply_v2,natural_semantic_ranges_v3,natural_segment_identity_v3
        from ..domains.d09 import segment_payload_digest
        from ..domains.d09.natural_disposition_v1 import NaturalChildDispositionV1,child_identity_manifest_v1
        from ..runtime_contracts import VersionedRef
        from ..runtime.jobs import get_job
        from datetime import datetime
        parsed=parse_natural_reply_output_v2(gen_observation.result["text"],generation_saved.frozen)
        parsed_review=parse_natural_reply_review_output_v1(review_observation.result["text"],saved.frozen,generation_saved.seal,saved.seal)
        generated=json.loads(parsed.canonical_output)
        if (parsed.status!="untrusted_content_candidate" or parsed.output_digest!=paid_request.generation_content_request.output_digest
                or parsed_review.output_digest!=paid_request.review_output_digest or parsed_review.verdict!=output.verdict
                or gen_observation.digest!=current.observation_digest or review_observation.digest!=output.observation_digest
                or parsed_review.verdict!="pass"
                or json.loads(parsed_review.canonical_output).get("prefix_safe") is not True):
            raise AuthorityUnavailable("natural roster has no complete prefix-safe paid original")
        plan=generation_saved.frozen.input.plan
        mechanical=mechanically_verify_natural_reply_v2(generated,plan=plan,current_reads=versions,now_utc=now)
        if mechanical.segment is None:
            raise AuthorityUnavailable("natural roster independent qualified mechanical candidate is unavailable")
        children=[]
        for index,(start,end) in enumerate(natural_semantic_ranges_v3(generated)):
            operation,effect,segment=natural_segment_identity_v3(plan,generated,index)
            uses=tuple(replace(use,start=use.start-start,end=use.end-start) for use in mechanical.segment.claim_uses if start<=use.start and use.end<=end)
            children.append(NaturalChildDispositionV1(
                index,operation,effect,segment,segment_payload_digest(generated["body"][start:end],(),uses)))
        parent=generation_saved.parent_original_id
        expected_attempt="natural-final:"+canonical_digest({"namespace":plan.namespace.as_tuple,"operation_id":children[0].operation_id})[:48]
        if permit.operation_id!=expected_attempt or permit.holder!=generation._holder:
            raise AuthorityUnavailable("natural roster preparation uses another actual first-final operation")
        original_ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,parent,"roster_prepared",children[0].operation_id)
        context,storage,member=self.owner._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("BEGIN")
            recovery=GraphStore._decode_recovery(db.execute("SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",plan.namespace.as_tuple).fetchone(),plan.namespace)
            epoch=db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",plan.namespace.as_tuple).fetchone()[0]
            job=get_job(db,generation_saved.seal.job_id)
            expires=min(generation_saved.frozen.input.expires_at_utc,plan.valid_until_utc,generation_binding.request.envelope.deadline_utc,
                datetime.fromisoformat(job.deadline_utc.replace("Z","+00:00")).timestamp())
        refs=tuple(VersionedRef(v.key.token,v.revision) for v in versions if v.key.type_name in {"memory.source","memory.access","d06.source_correction_head.v1"})
        value=NaturalBatchDispositionV1(plan.namespace,self.owner.installation_id,parent,plan.final_activity_id,
            generation_saved.seal.original_operation_id,canonical_digest(generation_saved.seal),saved.seal.original_operation_id,canonical_digest(saved.seal),
            parsed.output_digest,children[0].operation_id,canonical_digest(child_identity_manifest_v1(tuple(children))),refs,expires,tuple(children),
            birth_original_ref=original_ref,authority_original_ref=original_ref)
        from ..domains.d09.natural_disposition_v1 import natural_disposition_write_v1
        write=natural_disposition_write_v1(value)
        payload={"roster_ref":write.key.token,"expected_next_value":write.value,"next_payload_digest":canonical_digest(write.value),
            "prior_revision":0,"graph_revision":recovery.graph_revision,"graph_epoch":epoch,"requirements":asdict(recovery.requirements),
            "storage_commitment":canonical_digest(storage),"permit":to_wire(permit),"paid_request_digest":canonical_digest(paid_request),
            "generation_observation_digest":gen_observation.digest,"review_observation_digest":review_observation.digest,
            "read_versions":[{"ref":v.key.token,"revision":v.revision} for v in versions]}
        self.owner.control.verify_member_v1(member,prepared=False);context.require_current("business")
        # Repeat the same independently qualified read; never accept Host roster data.
        if paid_service._graph.read(paid_request,gen_intent,gen_receipt,review_intent,review_receipt,
                now_utc=now,credential=credential,subject=subject,fences=self.owner.fences,permit=permit,same_batch_prepared=None)!=original:
            raise AuthorityUnavailable("natural roster current paid/Source basis changed before Core sealing")
        with self.owner.fences._frozen() as (db,deletion,execution,_):
            actual=self.owner.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            if actual!=anchor:
                raise AuthorityUnavailable("natural roster actual first final anchor changed")
            self.owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=actual)
            self.owner._require_projection_pointer_in_tx_v1(db,context)
            return self.originals.append_in_tx(db,parent_original_id=parent,kind="roster_prepared",operation_id=children[0].operation_id,payload=payload)

    def confirm_original_v1(self, *, credential, subject, original_ref, permit):
        """Confirm an actual committed Graph projection using only signed metadata."""
        self._paired(credential,subject)
        prepared=self.originals.read(original_ref)
        if prepared is None or prepared.kind not in {"roster_prepared","maintenance_prepared"}:
            raise AuthorityUnavailable("natural disposition confirmation has no actual Core preparation")
        expected=natural_disposition_from_wire_v1(prepared.payload["expected_next_value"])
        committed_kind="roster_committed" if prepared.kind=="roster_prepared" else "maintenance_committed"
        known_ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,
            expected.parent_original_id,committed_kind,prepared.operation_id)
        known=self.originals.read(known_ref)
        if known is not None:
            if (known.payload["prepared_original_digest"]!=prepared.digest or known.payload["next_payload_digest"]!=prepared.payload["next_payload_digest"]
                    or from_wire(known.payload["permit"])!=permit):
                raise AuthorityUnavailable("natural confirmed original replay changed")
            return known
        actual_permit=from_wire(prepared.payload["permit"])
        if actual_permit!=permit or permit.subject!=subject or permit.operation!="write":
            raise AuthorityUnavailable("natural disposition confirmation crossed its original actual write permit")
        self.owner.fences._require_permit(credential=credential,subject=subject,permit=permit)
        # An unconfirmed finished permit is never an adoption certificate.
        self.owner.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        context,storage,member=self.owner._storage()
        if canonical_digest(storage)!=prepared.payload["storage_commitment"]:
            raise AuthorityUnavailable("natural disposition confirmation changed its original C09 Graph member")
        key=natural_disposition_key_v1(expected)
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            history=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",(key.token,expected.revision)).fetchone()
            event=db.execute("SELECT digest,reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                (*expected.namespace.as_tuple,expected.activity_id,prepared.operation_id)).fetchone()
            if history!=(prepared.operation_id,canonical_serialize(expected.to_wire()),1) or event is None:
                raise AuthorityUnavailable("natural disposition prepared original has no exact actual Graph commit")
            revisions=GraphStore._version_rows(event[2])
            if GraphVersion(key,expected.revision) not in revisions or event[3]!=prepared.payload["graph_epoch"]+1:
                raise AuthorityUnavailable("natural disposition actual Graph receipt/revision differs")
            if prepared.kind=="roster_prepared":
                bundle=db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                    (*expected.namespace.as_tuple,prepared.operation_id)).fetchone()
                fence=db.execute("SELECT permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,post_graph_epoch FROM graph_bundle_fences_v2 "
                    "WHERE bot=? AND persona=? AND operation_id=?",(*expected.namespace.as_tuple,prepared.operation_id)).fetchone()
                if (bundle is None or fence is None or from_wire(json.loads(fence[0]))!=permit
                        or fence[1:]!=(prepared.payload["graph_revision"],prepared.payload["graph_epoch"],
                            prepared.payload["graph_revision"]+1,prepared.payload["graph_epoch"]+1)):
                    raise AuthorityUnavailable("natural first roster has no actual normal final W01 receipt")
                adoption=json.loads(bundle[0]).get("natural_dispatch_candidate")
                if type(adoption) is not dict or len(adoption.get("refs",()))!=4:
                    raise AuthorityUnavailable("natural first roster has no actual paid dispatch candidate")
                receipt_digest=canonical_digest(json.loads(bundle[0]))
            else:
                if len(revisions)!=1 or revisions[0]!=GraphVersion(key,expected.revision):
                    raise AuthorityUnavailable("natural maintenance wrote outside its exact one-D09 key")
                receipt_digest=canonical_digest((event[0],event[1],event[2],event[3]))
        self.owner.control.verify_member_v1(member,prepared=False);context.require_current("business")
        payload={"prepared_original_ref":prepared.original_ref,"prepared_original_digest":prepared.digest,
            "roster_ref":key.token,"next_payload_digest":prepared.payload["next_payload_digest"],"next_revision":expected.revision,
            "graph_receipt_digest":receipt_digest,"post_graph_epoch":event[3],"permit":to_wire(permit),"storage_commitment":canonical_digest(storage)}
        kind="roster_committed" if prepared.kind=="roster_prepared" else "maintenance_committed"
        with self.owner.fences._frozen() as (db,deletion,execution,_):
            actual=self.owner.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            if actual!=permit.pinned_anchor:
                raise AuthorityUnavailable("natural confirmation current final Core anchor changed")
            self.owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=actual)
            self.owner._require_projection_pointer_in_tx_v1(db,context)
            return self.originals.append_in_tx(db,parent_original_id=expected.parent_original_id,kind=kind,operation_id=prepared.operation_id,payload=payload)

    def reject_original_no_commit_v1(self, *, credential, subject, original_ref, permit):
        """Exclude every in-flight family writer before recording an exact refusal."""
        self._paired(credential,subject)
        prepared=self.originals.read(original_ref)
        if (prepared is None or prepared.kind not in {"roster_prepared","maintenance_prepared"}
                or from_wire(prepared.payload["permit"])!=permit):
            raise AuthorityUnavailable("natural rejection requires its actual exact signed preparation")
        self.owner.fences._require_permit(credential=credential,subject=subject,permit=permit)
        context,storage,member=self.owner._storage()
        if canonical_digest(storage)!=prepared.payload["storage_commitment"]:
            raise AuthorityUnavailable("natural rejection cannot inspect another current C09 member")
        from ..runtime.natural_disposition_write_barrier_v1 import natural_final_graph_barrier_v1
        # The preliminary Core reads above have closed their transactions. No Core
        # mutex is held when the one-shot nonblocking inode barrier is acquired.
        with natural_final_graph_barrier_v1(graph_path=storage["graph_path"],
                expected_device=storage["graph_device"],expected_file_id=storage["graph_file_id"]) as barrier:
            return self._reject_prepared_in_barrier_v1(credential=credential,subject=subject,
                prepared=prepared,permit=permit,storage=storage,barrier=barrier)

    def _reject_prepared_in_barrier_v1(self, *, credential,subject,prepared,permit,storage,barrier):
        current_context,current_storage,current_member=self.owner._storage()
        if current_storage!=storage:
            raise AuthorityUnavailable("natural rejection current C09 pointer changed before its barrier")
        expected=natural_disposition_from_wire_v1(prepared.payload["expected_next_value"])
        rejected_ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,
            expected.parent_original_id,"rejected_no_commit",prepared.operation_id)
        known=self.originals.read(rejected_ref)
        if known is not None:
            if known.payload["prepared_original_digest"]!=prepared.digest or from_wire(known.payload["permit"])!=permit:
                raise AuthorityUnavailable("natural finished rejection replay changed its exact original")
            _actual,state=self.owner.fences.get_fence_operation(credential=credential,subject=subject,
                operation_id=permit.operation_id)
            if _actual!=permit or state!="finished":
                raise AuthorityUnavailable("natural rejected original did not finish its actual same permit")
            return known
        self.owner.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as graph:
            graph.execute("PRAGMA query_only=ON");graph.execute("BEGIN")
            recovery=GraphStore._decode_recovery(graph.execute("SELECT schema,requirements_json,graph_revision "
                "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",expected.namespace.as_tuple).fetchone(),expected.namespace)
            epoch=graph.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",expected.namespace.as_tuple).fetchone()[0]
            event=graph.execute("SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                (*expected.namespace.as_tuple,expected.activity_id,prepared.operation_id)).fetchone()
            history=graph.execute("SELECT 1 FROM graph_history WHERE token=? AND revision=? AND event_id=?",
                (natural_disposition_key_v1(expected).token,expected.revision,prepared.operation_id)).fetchone()
            if event is not None or history is not None:
                positive=True
            else:
                positive=False
                if (recovery.graph_revision,epoch)!=(prepared.payload["graph_revision"],prepared.payload["graph_epoch"]):
                    raise AuthorityUnavailable("natural refusal lost its exact original uncommitted Graph stamp")
                for table,where,args in (
                    ("graph_bundle_operations","bot=? AND persona=? AND operation_id=?",(*expected.namespace.as_tuple,prepared.operation_id)),
                    ("graph_bundle_fences_v2","bot=? AND persona=? AND operation_id=?",(*expected.namespace.as_tuple,prepared.operation_id)),
                    ("graph_dispatch_admissions","bot=? AND persona=? AND operation_id=?",(*expected.namespace.as_tuple,prepared.operation_id))):
                    if (graph.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None
                            and graph.execute("SELECT 1 FROM "+table+" WHERE "+where+" LIMIT 1",args).fetchone() is not None):
                        raise AuthorityUnavailable("natural original has adoption metadata; cannot assert no Graph commit")
        barrier.require_current_inode()
        self.owner.control.verify_member_v1(current_member,prepared=False);current_context.require_current("business")
        if positive:
            confirmed=self.confirm_original_v1(credential=credential,subject=subject,original_ref=prepared.original_ref,permit=permit)
            if prepared.kind=="roster_prepared":
                finish_id="finish:"+permit.operation_id
                finish_digest="sha256:"+canonical_digest({"action":"finish_natural_final","attempt_id":permit.operation_id,"permit_token":permit.token})
            else:
                finish_id="finish:"+permit.operation_id
                finish_digest="sha256:"+canonical_digest(("natural_disposition_finish.v1",prepared.operation_id,permit.token,prepared.digest))
            self.owner.fences.finish_fence(credential=credential,subject=subject,permit=permit,
                request_id=finish_id,request_digest=finish_digest)
            return confirmed
        payload={"prepared_original_ref":prepared.original_ref,"prepared_original_digest":prepared.digest,
            "permit":to_wire(permit),"storage_commitment":canonical_digest(storage),"state":"proven_no_graph_commit"}
        with self.owner.fences._frozen() as (db,deletion,execution,_):
            actual=self.owner.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            if actual!=permit.pinned_anchor:
                raise AuthorityUnavailable("natural refusal cannot close a changed original Core anchor")
            self.owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=actual)
            self.owner._require_projection_pointer_in_tx_v1(db,current_context)
            rejected=self.originals.append_in_tx(db,parent_original_id=expected.parent_original_id,
                kind="rejected_no_commit",operation_id=prepared.operation_id,payload=payload)
            self.owner.fences.fences.finish_fence_locked(db,permit,subject=subject,current_anchor=actual,
                request_id="reject:"+permit.operation_id,request_digest="sha256:"+canonical_digest(
                    ("natural_disposition_closed_refusal.v1",prepared.original_ref,prepared.digest,permit.token,canonical_digest(storage))))
            return rejected

    def reject_unprepared_write_no_commit_v1(self, *, credential, subject, request, permit):
        """Record the actual permit's unprepared refusal without inventing a parent."""
        self._paired(credential,subject)
        request=unprepared_closure_from_wire_v1(request.to_wire())
        require_unprepared_family_permit_v1(request,permit)
        if (request.namespace,request.installation_id)!=(self.owner.namespace_id,self.owner.installation_id):
            raise AuthorityUnavailable("natural unprepared closure crossed its actual installed scope")
        self.owner.fences._require_permit(credential=credential,subject=subject,permit=permit)
        context,storage,member=self.owner._storage()
        if (request.storage_commitment!=canonical_digest(storage) or request.graph_incarnation!=storage["graph_incarnation"]):
            raise AuthorityUnavailable("natural unprepared closure has no current C09 binding")
        from ..runtime.natural_disposition_write_barrier_v1 import natural_final_graph_barrier_v1
        with natural_final_graph_barrier_v1(graph_path=storage["graph_path"],
                expected_device=storage["graph_device"],expected_file_id=storage["graph_file_id"]) as barrier:
            context,current_storage,member=self.owner._storage()
            if current_storage!=storage:
                raise AuthorityUnavailable("natural unprepared closure C09 pointer changed")
            ref=natural_disposition_original_ref_v1(self.owner.namespace,self.owner.installation_id,None,"rejected_no_commit",permit.operation_id)
            known=self.originals.read(ref)
            if known is not None:
                if known.payload["scope"]!=request.to_wire() or from_wire(known.payload["permit"])!=permit:
                    raise AuthorityUnavailable("natural unprepared finished refusal replay changed")
                with self.owner.core._tx() as db:
                    validate_original_terminal_fence_in_tx_v1(db,known)
                return known
            self.owner.fences.validate_fence(credential=credential,subject=subject,permit=permit)
            with self.owner.core._tx() as db:
                rows=db.execute("SELECT payload_json,payload_digest,signature FROM "+ORIGINAL_TABLE+
                    " WHERE authority_namespace=? AND installation_id=? AND kind IN ('roster_prepared','maintenance_prepared') "
                    "AND json_extract(payload_json,'$.payload.permit.token')=? LIMIT 2",
                    (self.owner.namespace,self.owner.installation_id,permit.token)).fetchall()
            if len(rows)>1:
                raise AuthorityUnavailable("natural actual permit has ambiguous preparation")
            if rows:
                prepared=self.originals._decode(rows[0])
                if from_wire(prepared.payload["permit"])!=permit:
                    raise AuthorityUnavailable("natural preparation crossed its exact original permit")
                return self._reject_prepared_in_barrier_v1(credential=credential,subject=subject,
                    prepared=prepared,permit=permit,storage=storage,barrier=barrier)
            with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as graph:
                graph.execute("PRAGMA query_only=ON");graph.execute("BEGIN")
                recovery=GraphStore._decode_recovery(graph.execute("SELECT schema,requirements_json,graph_revision "
                    "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",request.namespace.as_tuple).fetchone(),request.namespace)
                epoch=graph.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",request.namespace.as_tuple).fetchone()[0]
                if (recovery.graph_revision,epoch,recovery.requirements.graph_incarnation)!=(request.graph_revision,request.graph_epoch,request.graph_incarnation):
                    raise AuthorityUnavailable("natural unprepared absence observation stamp differs")
                if graph.execute("SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND event_id=? LIMIT 1",
                        (*request.namespace.as_tuple,request.operation_id)).fetchone() is not None:
                    raise AuthorityUnavailable("natural unprepared scope has an actual Graph event")
                if graph.execute("SELECT 1 FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? LIMIT 1",
                        (*request.namespace.as_tuple,request.operation_id)).fetchone() is not None:
                    raise AuthorityUnavailable("natural unprepared scope has actual Graph history")
                for table in ("graph_bundle_operations","graph_bundle_fences_v2","graph_dispatch_admissions"):
                    if (graph.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None
                            and graph.execute("SELECT 1 FROM "+table+" WHERE bot=? AND persona=? AND operation_id=? LIMIT 1",
                                (*request.namespace.as_tuple,request.operation_id)).fetchone() is not None):
                        raise AuthorityUnavailable("natural unprepared scope has actual admission/commit metadata")
            barrier.require_current_inode()
            self.owner.control.verify_member_v1(member,prepared=False);context.require_current("business")
            with self.owner.fences._frozen() as (db,deletion,execution,_):
                actual=self.owner.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
                if actual!=permit.pinned_anchor:
                    raise AuthorityUnavailable("natural unprepared closure original Core anchor changed")
                self.owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=actual)
                self.owner._require_projection_pointer_in_tx_v1(db,context)
                if db.execute("SELECT 1 FROM "+ORIGINAL_TABLE+" WHERE authority_namespace=? AND installation_id=? "
                        "AND kind IN ('roster_prepared','maintenance_prepared') AND json_extract(payload_json,'$.payload.permit.token')=? LIMIT 1",
                        (self.owner.namespace,self.owner.installation_id,permit.token)).fetchone() is not None:
                    raise AuthorityUnavailable("natural original preparation completed before the final refusal")
                payload={"prepared_original_ref":None,"prepared_original_digest":None,"permit":to_wire(permit),
                    "storage_commitment":canonical_digest(storage),"scope":request.to_wire(),"state":"proven_no_preparation_no_graph_commit"}
                rejected=self.originals.append_in_tx(db,parent_original_id=None,kind="rejected_no_commit",operation_id=permit.operation_id,payload=payload)
                self.owner.fences.fences.finish_fence_locked(db,permit,subject=subject,current_anchor=actual,
                    request_id="reject:"+permit.operation_id,request_digest="sha256:"+canonical_digest(
                        ("natural_unprepared_closed_refusal.v1",permit.operation_id,permit.token,canonical_digest(request.to_wire()))))
                return rejected

    def read_roster_prepared_for_parent_v1(self, *, credential, subject, parent_original_id):
        self._paired(credential,subject)
        if type(parent_original_id) is not str or not 1<=len(parent_original_id)<=192:
            raise AuthorityUnavailable("natural Core roster lookup requires its exact parent identity")
        with self.owner.core._tx() as db:
            rows=db.execute("SELECT payload_json,payload_digest,signature FROM "+ORIGINAL_TABLE+
                " WHERE authority_namespace=? AND installation_id=? AND kind='roster_prepared' "
                "AND json_extract(payload_json,'$.parent_original_id')=? LIMIT 2",
                (self.owner.namespace,self.owner.installation_id,parent_original_id)).fetchall()
            if len(rows)>1:
                raise AuthorityUnavailable("natural Core parent has ambiguous actual roster preparation")
            return None if not rows else self.originals._decode(rows[0])

    def read_current_graph_identity_v1(self, *, credential, subject):
        self._paired(credential,subject)
        context,storage,member=self.owner._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            row=db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",self.owner.namespace_id.as_tuple).fetchone()
            if row is None or json.loads(row[0])["graph_incarnation"]!=storage["graph_incarnation"]:
                raise AuthorityUnavailable("natural current Graph identity lost its actual C09 incarnation")
        self.owner.control.verify_member_v1(member,prepared=False);context.require_current("business")
        with self.owner.fences._frozen() as (db,_deletion,_execution,_):
            self.owner._require_projection_pointer_in_tx_v1(db,context)
        return NaturalGraphIdentityV1(self.owner.namespace_id,self.owner.installation_id,storage["graph_path"],
            storage["graph_device"],storage["graph_file_id"],storage["graph_incarnation"],canonical_digest(storage))

    def read_original_v1(self, *, credential, subject, original_ref):
        self._paired(credential,subject)
        value=self.originals.read(original_ref)
        if value is None:
            raise AuthorityUnavailable("natural disposition actual immutable Core original is absent")
        return value

    def _paired(self, credential, subject):
        from .mtls_server import MtlsPeerCredential
        if type(credential) is not MtlsPeerCredential or subject != "mtls:sha256:" + credential.certificate_sha256:
            raise AuthorityUnavailable("natural metadata maintenance needs its actual paired Host subject")
        self.owner.core._require(credential, "current", self.owner.namespace)

    def _snapshot(self, *, parent_original_id):
        context, storage, member = self.owner._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
            try:
                head = read_natural_roster_head_v1(db,self.owner.namespace_id,parent_original_id)
            except (ValueError,TypeError) as exc:
                raise NaturalDispositionProjectionUnavailableV1("natural roster original cannot be projected") from exc
            if head is None:
                return None
            key, revision, value = head
            self._require_committed_head_v1(head)
            if value.installation_id != self.owner.installation_id:
                raise AuthorityUnavailable("natural metadata roster crossed its actual installation")
            recovery = GraphStore._decode_recovery(db.execute("SELECT schema,requirements_json,graph_revision "
                "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",self.owner.namespace_id.as_tuple).fetchone(),self.owner.namespace_id)
            epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",self.owner.namespace_id.as_tuple).fetchone()[0]
            versions = [GraphVersion(key,revision)]
            changes = []
            for ref in value.dependency_refs:
                row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?",(ref.ref,)).fetchone()
                actual = 0 if row is None else row[0]
                versions.append(GraphVersion(AtomKey.from_token(ref.ref),actual))
                if (ref.version == 0 and row is not None or ref.version > 0 and row != (ref.version,1)):
                    event = None if row is None else db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",(ref.ref,actual)).fetchone()
                    changes.append((ref.ref,actual,None if row is None else row[1],None if event is None else event[0]))
            adoptions = []
            for child in value.children:
                rows = db.execute("SELECT admission_ref FROM graph_dispatch_admissions WHERE bot=? AND persona=? AND operation_id=? AND effect_id=? LIMIT 2",
                    (*value.namespace.as_tuple,child.operation_id,child.effect_id)).fetchall()
                if len(rows)>1:
                    raise AuthorityUnavailable("natural child admission is ambiguous")
                adoptions.append(None if not rows else rows[0][0])
        self.owner.control.verify_member_v1(member,prepared=False)
        context.require_current("business")
        return context, storage, recovery, epoch, head, tuple(versions), tuple(changes), tuple(adoptions)

    def plan_v1(self, *, credential, subject, parent_original_id):
        self._paired(credential,subject)
        pending=self.originals.pending_maintenance(parent_original_id)
        if pending is not None:
            # ACK loss resumes the exact persisted original, never a new now/basis identity.
            return plan_from_wire_v1(pending.payload["plan"])
        snapshot = self._snapshot(parent_original_id=parent_original_id)
        if snapshot is None:
            return None
        context,storage,recovery,epoch,head,versions,changes,admissions = snapshot
        _,revision,value=head
        effects = tuple(self.execution.read_current_effect(credential=credential,subject=subject,effect_id=c.effect_id) for c in value.children)
        observations = []
        for effect in effects:
            if effect.state == "observed":
                receipt = self.execution.read_current_observation_receipt_v1(credential=credential,subject=subject,effect_id=effect.effect_id)
                observations.append((effect.effect_id,canonical_digest(receipt),receipt.pending.platform_observation.observation_id,receipt.pending.platform_observation.outcome))
        # Historical Stop proof is a fact. It does not reuse the initiating Owner grant.
        stop = None
        with self.owner.core._tx() as core:
            from .owner_stop_reply_v1 import PLAN_SCHEMA, validate_owner_stop_reply_core_row_v1
            from ..runtime.lifecycle_operations_v1 import decode_original
            for row in self.owner._rows(core):
                encoded=json.loads(row[7])
                if (encoded.get("schema")==PLAN_SCHEMA and encoded["scope"]["c02_operation_id"]==parent_original_id
                        and encoded["scope"]["namespace"]==asdict(value.namespace)
                        and encoded["request"]["installation_id"]==value.installation_id):
                    validate_owner_stop_reply_core_row_v1(row)
                    original=decode_original(json.loads(row[3]))
                    if original.activation_generation==recovery.requirements.activation_generation:
                        stop=(original.original_ref,original.original_digest.removeprefix("sha256:"))
                        break
        clock = None
        if self.clock_provider is not None:
            from .v2_clock import AuthorityClockReadingV2
            reading=self.clock_provider()
            if type(reading) is AuthorityClockReadingV2 and reading.healthy:
                clock=reading.utc_seconds+reading.utc_error_seconds
        children=[]
        for index,child in enumerate(value.children):
            if child.continuation_state in {"cancelled","superseded"}:
                children.append(child); continue
            if stop is not None:
                children.append(replace(child,continuation_state="cancelled",reason_code="owner_stop",cause_kind="owner_stop",cause_ref=stop[0],cause_digest=stop[1]));continue
            if changes:
                cause=changes[0]
                children.append(replace(child,continuation_state="held",reason_code="scoped_source_changed",cause_kind="graph_dependency_change",
                    cause_ref=cause[0],cause_digest=canonical_digest(cause)));continue
            if clock is not None and clock>=value.expires_at_utc:
                children.append(replace(child,continuation_state="held",reason_code="deadline_expired",cause_kind="clock_deadline",
                    cause_ref="natural-parent:"+value.parent_original_id,cause_digest=canonical_digest(("deadline_expired",value.expires_at_utc))));continue
            predecessor = None if index==0 else effects[index-1]
            if predecessor is not None and (predecessor.state=="unresolved" or predecessor.state=="observed" and predecessor.observation_outcome=="unknown"):
                children.append(replace(child,continuation_state="held",reason_code="predecessor_unknown",cause_kind="authority_effect_observation",
                    cause_ref=predecessor.effect_id,cause_digest=canonical_digest(predecessor)));continue
            if admissions[index] is not None or child.reason_code=="predecessor_unknown" and predecessor is not None and predecessor.observation_outcome in {"accepted","delivered"}:
                children.append(replace(child,continuation_state="ready",reason_code=None,cause_kind=None,cause_ref=None,cause_digest=None));continue
            # No current final admission is itself a qualification gap, not a proven cancellation.
            children.append(replace(child,continuation_state="held",reason_code="qualification_unavailable",cause_kind=None,cause_ref=None,cause_digest=None))
        changed=tuple(children)!=value.children
        next_value=replace(value,children=tuple(children),revision=revision+(1 if changed else 0),authority_original_ref=value.authority_original_ref)
        with self.owner.fences._frozen() as (db,deletion,execution,_):
            anchor=self.owner.fences._current_locked(db,deletion,execution)
            self.owner._require_projection_pointer_in_tx_v1(db,context)
        if (recovery.requirements.authority_id!=anchor.authority_id or recovery.requirements.authority_namespace!=anchor.namespace
                or recovery.requirements.activation_generation!=anchor.activation_generation
                or recovery.requirements.graph_incarnation!=storage["graph_incarnation"]):
            raise AuthorityUnavailable("natural metadata maintenance has no current installed C09 activation")
        basis=canonical_digest((value.namespace,value.installation_id,canonical_digest(value),anchor,
            recovery.graph_revision,epoch,canonical_digest(storage),revision,versions,changes,admissions,effects,observations,stop,children))
        if changed:
            next_value=replace(next_value,authority_original_ref=natural_disposition_original_ref_v1(
                self.owner.namespace,self.owner.installation_id,value.parent_original_id,"maintenance_prepared",
                "natural-disposition:"+canonical_digest((value.namespace,value.parent_original_id,revision,basis))[:40]))
        operation_id="natural-disposition:"+canonical_digest((value.namespace,value.parent_original_id,revision,basis))[:40]
        request=NaturalDispositionMaintenanceRequestV1(value.namespace,value.installation_id,value.parent_original_id,
            head[0].token,revision,operation_id,canonical_digest(next_value.to_wire()))
        return NaturalDispositionMaintenancePlanV1(request,anchor,recovery.requirements,recovery.graph_revision,epoch,
            versions,next_value,clock,basis,changed,canonical_digest(storage))

    @staticmethod
    def _fee_records_v1(db, namespace, *, operation_id=None, effect_id=None):
        from ..runtime.d11_types import RuntimeCostSettlement
        predicate = "json_extract(value,'$.bundle_operation_id')=?" if operation_id is not None else "json_extract(value,'$.effect_id')=?"
        rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='runtime.cost_settlement' AND valid=1 AND "
            +predicate+" ORDER BY token LIMIT 5",(*namespace.as_tuple,operation_id if operation_id is not None else effect_id)).fetchall()
        if len(rows)>4:
            raise AuthorityUnavailable("natural metadata expense originals exceed their finite bound")
        result=[]
        for token,revision,wire in rows:
            cost=RuntimeCostSettlement(**json.loads(wire))
            history=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",(token,revision)).fetchone()
            original=db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple,cost.bundle_operation_id)).fetchone()
            if history!=(cost.bundle_operation_id,wire,1) or original is None or (cost.bot_id,cost.persona_id)!=namespace.as_tuple:
                raise AuthorityUnavailable("natural metadata expense has no actual producing original")
            result.append(NaturalFeeMetadataV1(token,cost.status,cost.currency,
                None if cost.actual is None else dict(cost.actual),dict(cost.unconfirmed)))
        return tuple(result)

    def _parent_fee_records_v1(self, db, namespace, parent_original_id):
        from ..runtime.model_cost_settlement import original_model_cost_operation_id_v1
        fees=[]
        for stage in ("generation","review"):
            table="graph_natural_"+stage+"_preparations_v2"
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is None:
                continue  # No natural preparation schema exists before this stage was first used.
            call=db.execute("SELECT json_extract(seal_json,'$.call_id') FROM "+table+
                " WHERE bot=? AND persona=? AND parent_original_id=?",(*namespace.as_tuple,parent_original_id)).fetchone()
            if call is not None and call[0] is not None:
                fees.extend(self._fee_records_v1(db,namespace,operation_id=original_model_cost_operation_id_v1(namespace,call[0])))
        return tuple({fee.settlement_ref:fee for fee in fees}.values())

    def project_owner_metadata_v1(self, *, credential, subject, parent_original_id):
        """Called only inside the existing current Owner list authentication flow."""
        self._paired(credential,subject)
        try:
            snapshot=self._snapshot(parent_original_id=parent_original_id)
        except NaturalDispositionProjectionUnavailableV1:
            snapshot=None
        schema="d12.natural-batch-metadata.v1"
        if snapshot is None:
            context,storage,member=self.owner._storage()
            with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
                db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
                fees=self._parent_fee_records_v1(db,self.owner.namespace_id,parent_original_id)
            self.owner.control.verify_member_v1(member,prepared=False);context.require_current("business")
            return NaturalBatchMetadataV1(schema,parent_original_id,None,"bubble_details_unavailable",fees,())
        context,storage,recovery,epoch,head,versions,changes,admissions=snapshot
        value=head[2]
        child_fees=[]; intents=[]; parent_fees=[]
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri()+"?mode=ro",uri=True)) as db:
            db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
            actual=read_natural_roster_head_v1(db,value.namespace,parent_original_id)
            if actual!=head:
                raise AuthorityUnavailable("natural metadata roster changed during Owner projection")
            for child,admission in zip(value.children,admissions):
                if admission is None:
                    intents.append(None)
                else:
                    from ..runtime.dispatch_admission import load_admission
                    admitted=load_admission(db,value.namespace,admission)
                    if (admitted is None or admitted.admission.operation_id!=child.operation_id
                            or admitted.admission.effect_id!=child.effect_id
                            or admitted.admission.payload_digest!=child.payload_digest):
                        raise AuthorityUnavailable("natural metadata child admission original differs")
                    original=db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                        (*value.namespace.as_tuple,child.operation_id)).fetchone()
                    candidate=None if original is None else json.loads(original[0]).get("natural_dispatch_candidate")
                    if candidate is None or len(candidate.get("refs",()))!=4:
                        raise AuthorityUnavailable("natural metadata child intent has no actual adopted original")
                    intents.append(candidate["refs"][0][0])
                child_fees.append(self._fee_records_v1(db,value.namespace,effect_id=child.effect_id))
            parent_fees=self._parent_fee_records_v1(db,value.namespace,parent_original_id)
        # No model expense is repeated on a child. Actual child effect costs are separate.
        parent_fees=tuple({fee.settlement_ref:fee for fee in parent_fees}.values())
        parent_fee_refs={fee.settlement_ref for fee in parent_fees}
        child_fees=[tuple(fee for fee in fees if fee.settlement_ref not in parent_fee_refs) for fees in child_fees]
        children=[]
        for index,child in enumerate(value.children):
            authority_state="unavailable";outcome=None;observation_ref=None
            try:
                effect=self.execution.read_current_effect(credential=credential,subject=subject,effect_id=child.effect_id)
                authority_state=effect.state
                if effect.state=="observed":
                    receipt=self.execution.read_current_observation_receipt_v1(credential=credential,subject=subject,effect_id=child.effect_id)
                    observation=receipt.pending.platform_observation
                    if (observation.binding.origin.operation_id,observation.binding.origin.effect_id)!=(child.operation_id,child.effect_id):
                        raise AuthorityUnavailable("natural metadata observation crossed its actual child effect")
                    outcome=observation.outcome;observation_ref=observation.observation_id
            except AuthorityUnavailable:
                # A current observation gap is not absence, cancellation or zero cost.
                authority_state="unavailable";outcome=None;observation_ref=None
            children.append(NaturalBubbleMetadataV1(index,child.operation_id,child.effect_id,intents[index],admissions[index],
                child.continuation_state,child.reason_code,authority_state,outcome,observation_ref,"unknown",child_fees[index]))
        context.require_current("business")
        return NaturalBatchMetadataV1(schema,parent_original_id,head[1],"adopted",parent_fees,tuple(children))

    def observe_v1(self, *, credential, subject, request, permit):
        self._paired(credential,subject)
        if type(request) is not NaturalDispositionMaintenanceRequestV1 or type(permit) is not FencePermitV2 or permit.operation!="write":
            raise AuthorityUnavailable("natural disposition requires a named request and actual write permit")
        self.owner.fences._require_permit(credential=credential,subject=subject,permit=permit)
        self.owner.fences.validate_fence(credential=credential,subject=subject,permit=permit)
        plan=self.plan_v1(credential=credential,subject=subject,parent_original_id=request.parent_original_id)
        if plan is not None:
            snapshot=self._snapshot(parent_original_id=request.parent_original_id)
            if snapshot is None or (snapshot[2].graph_revision,snapshot[3],snapshot[4][1])!=(plan.graph_revision,plan.graph_epoch,request.expected_revision):
                raise AuthorityUnavailable("natural metadata prepared operation lost its original Graph qualification")
        if plan is None or plan.request!=request or plan.anchor!=permit.pinned_anchor or permit.operation_id!=request.operation_id:
            raise AuthorityUnavailable("natural disposition fixed metadata read plan changed before observation")
        with self.owner.fences._frozen() as (db,deletion,execution,_):
            anchor=self.owner.fences._current_locked(db,deletion,execution,holder=permit.holder,generation=permit.generation)
            if anchor!=plan.anchor:
                raise AuthorityUnavailable("natural disposition authority head changed before observation")
            self.owner.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=anchor)
            payload={"roster_ref":plan.request.roster_ref,"expected_next_value":plan.next_value.to_wire(),
                "next_payload_digest":plan.request.next_payload_digest,"prior_revision":plan.request.expected_revision,
                "graph_revision":plan.graph_revision,"graph_epoch":plan.graph_epoch,"requirements":asdict(plan.requirements),
                "storage_commitment":plan.storage_commitment,"permit":to_wire(permit),"plan":plan.to_wire()}
            prepared=self.originals.append_in_tx(db,parent_original_id=plan.request.parent_original_id,
                kind="maintenance_prepared",operation_id=plan.request.operation_id,payload=payload)
        return NaturalDispositionMaintenanceObservedV1(plan,permit,prepared)
