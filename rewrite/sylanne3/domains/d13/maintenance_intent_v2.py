"""Bodyless immutable D13 maintenance plans; neither locators nor DTOs grant access."""
from dataclasses import asdict, dataclass, fields
import math
from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

INTENT_TYPE = "d13.derived_cache_maintenance.v2"
WORK_KIND = "d13.derived-cache.maintenance.v2"

def _sha(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

@dataclass(frozen=True, slots=True)
class D13MaintenanceVictimV2:
    metadata_ref: str
    metadata_revision: int
    metadata_digest: str
    block_ref: str
    payload_digest: str
    payload_length_bytes: int
    origin_producer_digest: str
    first_commit_epoch: int
    expires_at_utc: float
    reason: str

    def __post_init__(self):
        key = AtomKey.from_token(self.metadata_ref)
        if (key.type_name != "d13.derived_block_metadata.v2" or key.owner.kind != "persona"
                or key.name != self.block_ref or type(self.metadata_revision) is not int
                or self.metadata_revision < 1 or not all(_sha(v) for v in
                    (self.metadata_digest, self.payload_digest, self.origin_producer_digest))
                or type(self.payload_length_bytes) is not int or not 1 <= self.payload_length_bytes <= 524288
                or type(self.first_commit_epoch) is not int or self.first_commit_epoch < 1
                or type(self.expires_at_utc) not in (float, int) or not math.isfinite(self.expires_at_utc)
                or self.reason not in {"expired", "capacity_fifo"}):
            raise ValueError("invalid exact bodyless D13 maintenance victim")

    @property
    def payload_identity(self):
        return (self.block_ref, self.payload_digest, self.origin_producer_digest, self.metadata_revision)

    @property
    def fifo_key(self):
        return self.first_commit_epoch, self.metadata_ref

@dataclass(frozen=True, slots=True)
class D13DerivedCacheMaintenanceIntentV2:
    namespace: NamespaceId
    operation_id: str
    trigger_kind: str
    trigger_original_ref: str
    trigger_original_digest: str
    trigger_worker_fence: int | None
    trigger_source_heads: tuple
    trigger_authority_epochs: tuple
    policy_digest: str
    grant_digest: str
    original_deadline_utc: float
    additional_bytes: int
    additional_count: int
    retained_bytes: int
    retained_count: int
    inventory_digest: str
    classification_digest: str
    coverage_ref: str
    coverage_digest: str
    victims: tuple[D13MaintenanceVictimV2, ...]
    skipped_pinned: int
    skipped_unknown: int
    schema: str = INTENT_TYPE

    def __post_init__(self):
        if (self.schema != INTENT_TYPE or type(self.namespace) is not NamespaceId
                or type(self.operation_id) is not str or not self.operation_id.startswith("d13-maint-pass:")
                or self.trigger_kind not in {"cold", "pending_paid_payload"}
                or not self.trigger_original_ref or not self.coverage_ref
                or not all(_sha(v) for v in (self.trigger_original_digest, self.policy_digest,
                    self.grant_digest, self.inventory_digest, self.classification_digest, self.coverage_digest))
                or type(self.original_deadline_utc) not in (float, int)
                or not math.isfinite(self.original_deadline_utc)
                or type(self.victims) is not tuple or not 1 <= len(self.victims) <= 16
                or any(type(v) is not D13MaintenanceVictimV2 for v in self.victims)
                or len({v.metadata_ref for v in self.victims}) != len(self.victims)):
            raise ValueError("invalid exact D13 immutable maintenance intent")
        for value in (self.additional_bytes, self.additional_count, self.retained_bytes,
                self.retained_count, self.skipped_pinned, self.skipped_unknown):
            if type(value) is not int or value < 0:
                raise ValueError("D13 maintenance counts require exact nonnegative integers")
        if self.additional_count not in (0, 1) or self.additional_bytes > 524288:
            raise ValueError("maintenance cannot fabricate speculative capacity pressure")
        if self.trigger_kind == "cold" and (self.additional_count or self.additional_bytes or self.trigger_worker_fence is not None
                or self.trigger_source_heads or self.trigger_authority_epochs):
            raise ValueError("cold maintenance has no pending admission")
        if self.trigger_kind == "pending_paid_payload" and (self.additional_count != 1 or not self.additional_bytes
                or type(self.trigger_worker_fence) is not int or self.trigger_worker_fence < 1):
            raise ValueError("pending maintenance needs the exact actual one payload")
        if self.trigger_kind == "pending_paid_payload":
            if (type(self.trigger_source_heads) is not tuple or not 1 <= len(self.trigger_source_heads) <= 192
                    or type(self.trigger_authority_epochs) is not tuple or len(self.trigger_authority_epochs) != 2
                    or any(type(value) is not int or value < 0 for value in self.trigger_authority_epochs)):
                raise ValueError("pending cache admission lacks its original Source/Access metadata closure")
            for point in self.trigger_source_heads:
                if (type(point) is not tuple or len(point) != 4 or type(point[1]) is not int
                        or point[1] < 1 or point[2] != 1 or type(point[3]) is not str
                        or NamespaceId.from_key(AtomKey.from_token(point[0])) != self.namespace):
                    raise ValueError("pending Source head crossed its exact current namespace/identity")
        ranks = [(0 if v.reason == "expired" else 1, *v.fifo_key) for v in self.victims]
        if ranks != sorted(ranks) or any(NamespaceId.from_key(AtomKey.from_token(v.metadata_ref)) != self.namespace
                for v in self.victims):
            raise ValueError("maintenance victims changed eligible FIFO order or namespace")

    @property
    def digest(self):
        return canonical_digest(asdict(self))

def maintenance_intent_key_v2(intent):
    if type(intent) is not D13DerivedCacheMaintenanceIntentV2:
        raise TypeError("exact immutable maintenance intent required")
    return AtomKey(Owner("persona", *intent.namespace.as_tuple), INTENT_TYPE, intent.operation_id)

def decode_maintenance_intent_v2(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(D13DerivedCacheMaintenanceIntentV2)}:
        raise ValueError("maintenance intent has another closed schema")
    value = dict(raw)
    if type(value["namespace"]) is not dict or set(value["namespace"]) != {"bot_id", "persona_id"}:
        raise ValueError("maintenance intent namespace has another exact shape")
    value["namespace"] = NamespaceId(**value["namespace"])
    if type(value["victims"]) is not list:
        raise ValueError("maintenance victim inventory has another exact shape")
    names = {f.name for f in fields(D13MaintenanceVictimV2)}
    if any(type(v) is not dict or set(v) != names for v in value["victims"]):
        raise ValueError("maintenance victim has another closed schema")
    value["victims"] = tuple(D13MaintenanceVictimV2(**v) for v in value["victims"])
    if type(value["trigger_source_heads"]) is not list or type(value["trigger_authority_epochs"]) is not list:
        raise ValueError("pending trigger metadata has another closed sequence shape")
    value["trigger_source_heads"] = tuple(tuple(point) for point in value["trigger_source_heads"])
    value["trigger_authority_epochs"] = tuple(value["trigger_authority_epochs"])
    return D13DerivedCacheMaintenanceIntentV2(**value)

def maintenance_intent_type_specs_v2():
    return (TypeSpec(INTENT_TYPE, ("persona",), "state", decode_maintenance_intent_v2,
        immutable=True, writer_domain="d13", schema_version=2,
        schema_hash=schema_hash({"type": INTENT_TYPE, "version": 2,
            "scope": "namespace_derived_payload_only", "originals": "preserve_paid_and_history",
            "order": "metadata_first_commit_epoch_v1", "victims": 16,
            "pending": "exact_original_source_access_heads_and_worker_v2"})),)

def victim_operation_v2(intent, ordinal):
    if type(intent) is not D13DerivedCacheMaintenanceIntentV2 or type(ordinal) is not int or not 0 <= ordinal < len(intent.victims):
        raise ValueError("actual immutable victim ordinal required")
    v = intent.victims[ordinal]
    digest = canonical_digest((intent.digest, ordinal, v.metadata_ref, v.metadata_revision, v.reason))
    return "d13-maint-victim:" + digest[:48], digest
