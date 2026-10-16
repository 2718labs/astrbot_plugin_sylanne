"""Fixed user management cancellation facts; no Goal or Source body permission."""
from dataclasses import asdict, dataclass, fields
from uuid import UUID
import json
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable
from .v2_owner_contract import OwnerAuthorizationGuardV1

GOAL_CANCEL_SIGN_KIND_V1 = "authority.owner-goal-cancellation.v1"
GOAL_CANCEL_TABLE_V1 = "authority_owner_goal_cancellations_v1"
GOAL_CANCEL_COLUMNS_V1 = ("authority_namespace", "installation_id", "cancel_operation_id", "goal_ref",
    "root_registration_ref", "request_digest", "original_json", "original_digest", "signature")
GOAL_CANCEL_DDL_V1 = """CREATE TABLE authority_owner_goal_cancellations_v1(
    authority_namespace TEXT NOT NULL, installation_id TEXT NOT NULL, cancel_operation_id TEXT NOT NULL,
    goal_ref TEXT NOT NULL, root_registration_ref TEXT NOT NULL, request_digest TEXT NOT NULL,
    original_json TEXT NOT NULL, original_digest TEXT NOT NULL, signature TEXT NOT NULL,
    PRIMARY KEY(authority_namespace,installation_id,cancel_operation_id)) STRICT"""


def _digest_v1(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("exact cancellation original commitment required")


@dataclass(frozen=True, slots=True)
class OwnerGoalCancellationRequestV1:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    cancel_operation_id: str
    goal_ref: str
    expected_goal_atom_revision: int
    expected_goal_semantic_revision: int
    goal_producing_operation_id: str
    goal_producing_digest: str
    c02_operation_id: str
    root_registration_ref: str
    root_registration_digest: str
    schema: str = "d08.owner-goal-cancellation-request.v1"

    def __post_init__(self):
        key = AtomKey.from_token(self.goal_ref)
        if (type(self.namespace) is not NamespaceId or NamespaceId.from_key(key) != self.namespace
                or key.type_name != "d08.goal.v1" or key.owner.kind != "activity"
                or self.schema != "d08.owner-goal-cancellation-request.v1"
                or str(UUID(self.cancel_operation_id)) != self.cancel_operation_id
                or type(self.expected_goal_atom_revision) is not int or self.expected_goal_atom_revision < 1
                or type(self.expected_goal_semantic_revision) is not int or self.expected_goal_semantic_revision < 1):
            raise ValueError("exact current Goal management selector and user UUID required")
        for value in (self.authority_namespace, self.installation_id, self.goal_producing_operation_id,
                self.c02_operation_id, self.root_registration_ref):
            if type(value) is not str or not value or len(value.encode("utf8")) > 4096:
                raise ValueError("registered management cancellation locator required")
        _digest_v1(self.goal_producing_digest); _digest_v1(self.root_registration_digest)

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class GoalCancellationMetadataV1:
    namespace: NamespaceId
    goal_ref: str
    goal_atom_revision: int
    goal_semantic_revision: int
    goal_id: str
    goal_state: str
    goal_payload_digest: str
    goal_producing_operation_id: str
    goal_producing_digest: str
    c02_operation_id: str
    root_registration_ref: str
    root_registration_digest: str
    graph_revision: int
    graph_epoch: int
    selection_digest: str
    schema: str = "d08.goal-cancellation-metadata.v1"

    def __post_init__(self):
        key = AtomKey.from_token(self.goal_ref)
        if (self.schema != "d08.goal-cancellation-metadata.v1" or type(self.namespace) is not NamespaceId
                or NamespaceId.from_key(key) != self.namespace or key.type_name != "d08.goal.v1"
                or key.name != self.goal_id
                or self.goal_state not in {"proposed","active","waiting","paused","satisfied","abandoned","superseded"}
                or any(type(getattr(self, name)) is not int or getattr(self, name) < 1 for name in
                    ("goal_atom_revision", "goal_semantic_revision", "graph_revision", "graph_epoch"))):
            raise ValueError("actual current Goal metadata has another fixed variant")
        for name in ("goal_payload_digest", "goal_producing_digest", "root_registration_digest", "selection_digest"):
            _digest_v1(getattr(self, name))

    def require_request_v1(self, request):
        if type(request) is not OwnerGoalCancellationRequestV1 or (
                self.namespace, self.goal_ref, self.goal_atom_revision, self.goal_semantic_revision,
                self.goal_producing_operation_id, self.goal_producing_digest, self.c02_operation_id,
                self.root_registration_ref, self.root_registration_digest) != (
                request.namespace, request.goal_ref, request.expected_goal_atom_revision,
                request.expected_goal_semantic_revision, request.goal_producing_operation_id,
                request.goal_producing_digest, request.c02_operation_id, request.root_registration_ref,
                request.root_registration_digest):
            raise AuthorityUnavailable("current Goal metadata no longer matches the actual user request")
        return self


@dataclass(frozen=True, slots=True)
class OwnerGoalCancellationOriginalV1:
    request: OwnerGoalCancellationRequestV1
    metadata: GoalCancellationMetadataV1
    authority_id: str
    actor_id: str
    principal_json: str
    credential_id: str
    credential_epoch: int
    session_request_digest: str
    session_request_json: str
    session_principal_epoch: int
    session_boot_id: str
    owner_guard: OwnerAuthorizationGuardV1
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    metadata_operation_id: str
    metadata_deadline_utc: str
    anchor: RestoreAnchor
    active_originals_commitment: str
    storage_pointer_version: int
    storage_manifest_digest: str
    storage_generation: int
    source_graph_incarnation: str
    cancel_scope: str
    state: str
    original_ref: str
    signature: str
    schema: str = "d08.owner-goal-cancellation-original.v1"

    def __post_init__(self):
        if (type(self.request) is not OwnerGoalCancellationRequestV1 or type(self.metadata) is not GoalCancellationMetadataV1
                or type(self.owner_guard) is not OwnerAuthorizationGuardV1 or type(self.anchor) is not RestoreAnchor
                or self.schema != "d08.owner-goal-cancellation-original.v1" or self.cancel_scope != "artifact_task_goal"
                or self.state != "cancel_requested"
                or self.anchor.authority_id != self.authority_id or self.anchor.namespace != self.request.authority_namespace
                or self.owner_guard.namespace != self.request.namespace or not self.signature
                or self.original_ref != "owner-goal-cancellation:" + canonical_digest((self.request.namespace,
                    self.request.installation_id, self.request.cancel_operation_id))):
            raise ValueError("fixed signed Core Goal cancellation original required")
        self.metadata.require_request_v1(self.request)
        session = json.loads(self.session_request_json)
        if (canonical_serialize(session) != self.session_request_json
                or canonical_digest(session) != self.session_request_digest):
            raise ValueError("actual signed initiating Owner request metadata differs")
        for name in ("session_request_digest", "owner_grant_digest", "active_originals_commitment", "storage_manifest_digest"):
            _digest_v1(getattr(self, name))
        from ..runtime.d11_offline_originals_v1 import _utc
        _utc(self.metadata_deadline_utc)
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 1 for name in
                ("credential_epoch", "owner_grant_revision", "storage_pointer_version", "storage_generation")):
            raise ValueError("actual Owner/session/storage revisions required")

    @property
    def unsigned_wire(self):
        raw = asdict(self); raw.pop("signature"); return raw

    @property
    def digest(self):
        return canonical_digest(self.unsigned_wire)

    def require_signature_v1(self, issuer):
        issuer._signer.verify(GOAL_CANCEL_SIGN_KIND_V1, canonical_serialize(self.unsigned_wire), self.signature)
        return self


def owner_goal_cancellation_from_wire_v1(raw, kind):
    if kind not in {OwnerGoalCancellationRequestV1, GoalCancellationMetadataV1, OwnerGoalCancellationOriginalV1}:
        raise ValueError("unregistered Goal cancellation codec")
    if type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("closed Goal cancellation fields differ")
    data = dict(raw)
    if kind is OwnerGoalCancellationOriginalV1:
        data["request"] = owner_goal_cancellation_from_wire_v1(data["request"], OwnerGoalCancellationRequestV1)
        data["metadata"] = owner_goal_cancellation_from_wire_v1(data["metadata"], GoalCancellationMetadataV1)
        data["anchor"] = RestoreAnchor(**data["anchor"])
        data["owner_guard"] = OwnerAuthorizationGuardV1(**{**data["owner_guard"],
            "namespace": NamespaceId(**data["owner_guard"]["namespace"])})
    else:
        data["namespace"] = NamespaceId(**data["namespace"])
    value = kind(**data)
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(value) != raw: raise ValueError("Goal cancellation canonical roundtrip differs")
    return value


def require_goal_not_cancelled_in_tx_v1(db, *, service, goal_ref, c02_operation_id, root_registration_ref, action):
    from .owner_goal_cancellation_v1 import InstalledOwnerGoalCancellationServiceV1
    if (type(service) is not InstalledOwnerGoalCancellationServiceV1 or db is not service.core._db
            or not db.in_transaction or action not in {"model_prepare", "model_admit", "model_result_body",
                "first_claim", "phase_execute", "action_admission"}):
        raise AuthorityUnavailable("actual fixed Goal cancellation gate required")
    rows = db.execute("SELECT original_json,original_digest,signature FROM " + GOAL_CANCEL_TABLE_V1 +
        " WHERE authority_namespace=? AND installation_id=? AND goal_ref=? AND root_registration_ref=? "
        "ORDER BY cancel_operation_id LIMIT 2", (service.namespace, service.installation_id, goal_ref, root_registration_ref)).fetchall()
    if rows:
        original = owner_goal_cancellation_from_wire_v1(json.loads(rows[0][0]), OwnerGoalCancellationOriginalV1)
        original.require_signature_v1(service.issuer)
        if (rows[0][1], rows[0][2], original.request.c02_operation_id) != (
                original.digest, original.signature, c02_operation_id):
            raise AuthorityUnavailable("durable Goal cancellation barrier changed its original target")
        raise AuthorityUnavailable("actual_owner_goal_cancellation_barrier:" + original.original_ref)


def validate_goal_cancellation_core_row_v1(columns, row, *, issuer=None):
    if tuple(columns)!=GOAL_CANCEL_COLUMNS_V1 or len(row)!=len(GOAL_CANCEL_COLUMNS_V1):
        raise AuthorityUnavailable("actual Goal cancellation Core columns differ")
    raw=json.loads(row[6])
    value=owner_goal_cancellation_from_wire_v1(raw,OwnerGoalCancellationOriginalV1)
    if (row[:6]!=(value.request.authority_namespace,value.request.installation_id,
            value.request.cancel_operation_id,value.request.goal_ref,
            value.request.root_registration_ref,value.request.digest)
            or row[6:]!=(canonical_serialize(raw),value.digest,value.signature)):
        raise AuthorityUnavailable("Goal cancellation Core original changed its immutable exact joins")
    if issuer is not None:value.require_signature_v1(issuer)
    return value
