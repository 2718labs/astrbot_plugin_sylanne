"""Current signed Owner StopReply intent in the existing installed D12 ledger."""
from contextlib import closing
from dataclasses import asdict, dataclass, fields, replace
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from uuid import UUID
import weakref

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1
from .d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
from .v2_owner_session import _canonical
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from .v2_owner_contract import (OwnerAuthorizationGuardV1,
    from_wire as owner_from_wire, to_wire as owner_to_wire)
from ..domains.d12.backend_operation_contracts_v1 import (
    SCHEMA, D12BackendOperationOriginalV1, D12ControlPayloadV1, backend_original_digest_v1)
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime.issuers import D11BudgetJobIssuer
from ..runtime.lifecycle_operations_v1 import OwnerOperationBindingV1, decode_original, digest
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest, canonical_serialize

REQUEST_SCHEMA = "d12.owner-stop-reply-request.v1"
PLAN_SCHEMA = "d12.registered_owner_stop_reply.v1"
_PLAN_FIELDS = frozenset({"schema", "request", "scope", "owner", "storage", "graph_snapshot", "child_originals", "target_cancel_generation"})
_SCOPE_FIELDS = frozenset({"namespace", "c02_operation_id", "cycle_job_ref", "create_operation_id", "create_original_ref", "create_original_digest", "c02_receipt_digest", "responsibility_ref", "responsibility_digest"})
_STOP_ACTIONS = frozenset({"foreground", "model_prepare", "model_admit", "model_result", "content_adoption", "natural_generation", "natural_review", "natural_final", "message_claim", "tool_claim", "c04_claim"})
_RETIREMENT_KIND = "owner_reply_cycle_stop_v1"
_CONSUMED_COLUMNS = ("namespace", "kind", "item_id", "operation_id", "original_commitment", "facts_pin_digest")


def owner_reply_cycle_retirement_commitment_v1(authority_namespace, cycle_job_ref, stop_operation_id):
    """The same exact C09 producer/reader commitment, without a new ledger."""
    if type(stop_operation_id) is not str:
        raise ValueError("canonical retired StopReply UUID4 required")
    operation = UUID(stop_operation_id)
    if (type(authority_namespace) is not str or not authority_namespace
            or AtomKey.from_token(cycle_job_ref).type_name != "runtime.job"
            or operation.version != 4 or str(operation) != stop_operation_id):
        raise ValueError("exact retired Owner reply cycle identity required")
    wire = json.dumps(("sylanne.owner-reply-cycle-stop-retired.v1", authority_namespace,
        cycle_job_ref, stop_operation_id), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(wire).hexdigest()


@dataclass(frozen=True, slots=True)
class OwnerStopReplyRequestV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    cycle_job_ref: str
    c02_operation_id: str
    expected_cancel_generation: int
    schema: str = REQUEST_SCHEMA

    def __post_init__(self):
        if self.schema != REQUEST_SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("exact StopReply request namespace/schema required")
        if type(self.operation_id) is not str or type(self.cycle_job_ref) is not str:
            raise ValueError("StopReply operation and cycle locator must be exact strings")
        parsed = UUID(self.operation_id)
        key = AtomKey.from_token(self.cycle_job_ref)
        if (parsed.version != 4 or str(parsed) != self.operation_id
                or key.type_name != "runtime.job" or NamespaceId.from_key(key) != self.namespace
                or type(self.installation_id) is not str or not 1 <= len(self.installation_id) <= 256
                or type(self.c02_operation_id) is not str or not 1 <= len(self.c02_operation_id) <= 256
                or type(self.expected_cancel_generation) is not int or self.expected_cancel_generation < 0):
            raise ValueError("StopReply requires its finite real cycle identity and canonical UUID4")

    def to_wire(self):
        return asdict(self)


def owner_stop_reply_request_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(OwnerStopReplyRequestV1.__dataclass_fields__):
        raise ValueError("StopReply request fields differ")
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    result = OwnerStopReplyRequestV1(**data)
    if result.to_wire() != raw:
        raise ValueError("StopReply request wire is not canonical")
    return result


@dataclass(frozen=True, slots=True)
class OwnerReplyControlMetadataV1:
    namespace: NamespaceId
    installation_id: str
    cycle_job_ref: str
    c02_operation_id: str
    cancel_generation: int
    job_phase: str
    original_ref: str | None
    stop_state: str | None
    schema: str = "d12.owner-reply-control-metadata.v1"

    def __post_init__(self):
        from ..runtime.jobs import _PHASES
        key = AtomKey.from_token(self.cycle_job_ref)
        if (self.schema != "d12.owner-reply-control-metadata.v1" or type(self.namespace) is not NamespaceId
                or NamespaceId.from_key(key) != self.namespace or key.type_name != "runtime.job"
                or type(self.installation_id) is not str or not self.installation_id
                or type(self.c02_operation_id) is not str or not self.c02_operation_id
                or type(self.cancel_generation) is not int or self.cancel_generation < 0 or self.job_phase not in _PHASES
                or (self.original_ref is None) != (self.stop_state is None)
                or self.stop_state not in {None, "cancel_requested", "pending_confirmation", "cancelled"}):
            raise ValueError("exact Owner reply control metadata required")

    def to_wire(self):
        return asdict(self)


@dataclass(frozen=True, slots=True)
class OwnerReplyControlMetadataV2(OwnerReplyControlMetadataV1):
    natural_batch: dict | None = None
    schema: str = "d12.owner-reply-control-metadata.v2"

    def __post_init__(self):
        OwnerReplyControlMetadataV1(self.namespace,self.installation_id,self.cycle_job_ref,self.c02_operation_id,
            self.cancel_generation,self.job_phase,self.original_ref,self.stop_state)
        if self.schema!="d12.owner-reply-control-metadata.v2":
            raise ValueError("exact Owner reply metadata v2 required")
        if self.natural_batch is not None:
            from .natural_disposition_maintenance_v1 import validate_owner_natural_batch_metadata_v1
            validate_owner_natural_batch_metadata_v1(self.natural_batch,self.c02_operation_id)


def owner_reply_control_metadata_from_wire_v1(raw):
    kind=OwnerReplyControlMetadataV2 if type(raw) is dict and raw.get("schema")=="d12.owner-reply-control-metadata.v2" else OwnerReplyControlMetadataV1
    if type(raw) is not dict or set(raw) != set(kind.__dataclass_fields__):
        raise ValueError("Owner reply control metadata fields differ")
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    result = kind(**data)
    if result.to_wire() != raw:
        raise ValueError("Owner reply control metadata wire is not canonical")
    return result


@dataclass(frozen=True, slots=True)
class OwnerReplyControlPageV1:
    items: tuple[OwnerReplyControlMetadataV1, ...]
    next_cursor: str | None


def _read_owner_reply_control_targets_v1(db, namespace, cursor):
    """Page current work first, using its immutable create commit sequence."""
    after = None
    if cursor is not None:
        if type(cursor) is not str or not 1 <= len(cursor) <= 256:
            raise ValueError("bounded Owner reply control cursor required")
        after = json.loads(cursor)
        if (type(after) is not list or len(after) != 3
                or type(after[0]) is not int or after[0] not in {0, 1}
                or type(after[1]) is not int or after[1] < 1
                or type(after[2]) is not str or not 1 <= len(after[2]) <= 128
                or canonical_serialize(after) != cursor):
            raise ValueError("canonical Owner reply control cursor required")
    rank = "CASE WHEN j.phase IN ('completed','failed','cancelled') THEN 1 ELSE 0 END"
    sql = ("SELECT j.job_id,j.continuation_json," + rank + ",b.commit_seq "
        "FROM runtime_jobs j JOIN graph_bundle_operations b "
        "ON b.bot=j.bot_id AND b.persona=j.persona_id AND b.operation_id=j.operation_id "
        "WHERE j.bot_id=? AND j.persona_id=? AND j.work_kind='d11.foreground_cycle.v1' "
        "AND COALESCE(json_extract(j.continuation_json,'$.schema'),'')<>"
        "'d11.owner-source-note-task-continuation.v2'")
    values = namespace.as_tuple
    if after is not None:
        sql += (" AND (" + rank + ">? OR (" + rank + "=? AND "
            "(b.commit_seq<? OR (b.commit_seq=? AND j.job_id>?))))")
        values += (after[0], after[0], after[1], after[1], after[2])
    sql += " ORDER BY " + rank + " ASC,b.commit_seq DESC,j.job_id ASC LIMIT 33"
    rows = tuple(db.execute(sql, values))
    selected = rows[:32]
    next_cursor = (canonical_serialize([selected[-1][2], selected[-1][3], selected[-1][0]])
        if len(rows) > 32 else None)
    return tuple((row[0], row[1]) for row in selected), next_cursor


@dataclass(frozen=True, slots=True)
class OwnerStopReplyProjectionObservedV1:
    """Paired-channel facts; only the private consumer can bind a W01 witness."""
    request: OwnerStopReplyRequestV1
    initial_original: D12BackendOperationOriginalV1
    permit: FencePermitV2
    owner_actor_ref: str
    owner_authorization: OwnerAuthorizationGuardV1
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    requirements: SnapshotRequirementsV2
    graph_revision: int
    graph_epoch: int
    read_versions: tuple[GraphVersion, ...]
    storage_pointer_version: int
    storage_generation: int
    source_location_digest: str
    schema: str = "d12.owner-stop-reply-projection-observed.v1"

    def __post_init__(self):
        if (self.schema != "d12.owner-stop-reply-projection-observed.v1"
                or type(self.request) is not OwnerStopReplyRequestV1 or type(self.permit) is not FencePermitV2
                or type(self.owner_authorization) is not OwnerAuthorizationGuardV1
                or type(self.requirements) is not SnapshotRequirementsV2):
            raise ValueError("exact StopReply projection observation types required")
        require_owner_stop_reply_original_v1(self.initial_original, request=self.request)
        original, permit, owner, req = self.initial_original, self.permit, self.owner_authorization, self.requirements
        if (original.state != "cancel_requested" or permit.operation != "write"
                or permit.operation_id != "owner-stop-projection:" + original.operation_id
                or (permit.authority_id, permit.namespace, permit.generation) != (
                    req.authority_id, req.authority_namespace, req.activation_generation)
                or req.namespace != self.request.namespace or original.activation_generation != permit.generation
                or (owner.authority_id, owner.installation_id, owner.namespace) != (
                    permit.authority_id, self.request.installation_id, self.request.namespace)
                or ("owner", "owner-authority:" + owner.authorization_head, digest(owner)) not in original.authority_refs
                or type(self.owner_actor_ref) is not str or not self.owner_actor_ref
                or (self.owner_grant_ref, self.owner_grant_revision, "sha256:" + self.owner_grant_digest)
                    != (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest)):
            raise ValueError("StopReply observation permit/current Owner/original identity differs")
        if (any(type(value) is not int or value < 0 for value in (self.graph_revision, self.graph_epoch))
                or any(type(value) is not int or value < 1 for value in (self.storage_pointer_version, self.storage_generation))
                or any(type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None
                    for value in (self.owner_grant_digest, self.source_location_digest))
                or type(self.read_versions) is not tuple or any(type(value) is not GraphVersion
                    or NamespaceId.from_key(value.key) != self.request.namespace for value in self.read_versions)
                or len({value.key for value in self.read_versions}) != len(self.read_versions)
                or GraphVersion(AtomKey.from_token(self.owner_grant_ref), self.owner_grant_revision) not in self.read_versions
                or not any(value.key.token == self.request.cycle_job_ref for value in self.read_versions)):
            raise ValueError("StopReply observation actual metadata stamp/read set differs")

    @property
    def digest(self):
        return canonical_digest(self.to_wire())

    def to_wire(self):
        result = asdict(self)
        result.update(request=self.request.to_wire(), initial_original=self.initial_original.to_wire(),
            permit=fence_to_wire(self.permit), owner_authorization=owner_to_wire(self.owner_authorization),
            requirements=asdict(self.requirements),
            read_versions=[{"key": version.key.token, "revision": version.revision} for version in self.read_versions])
        return result


def owner_stop_reply_projection_observed_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(OwnerStopReplyProjectionObservedV1.__dataclass_fields__):
        raise ValueError("StopReply projection observation fields differ")
    data = dict(raw)
    data["request"] = owner_stop_reply_request_from_wire_v1(data["request"])
    data["initial_original"] = decode_original(data["initial_original"])
    data["permit"] = fence_from_wire(data["permit"])
    data["owner_authorization"] = owner_from_wire(data["owner_authorization"])
    requirements = dict(data["requirements"])
    requirements["namespace"] = NamespaceId(**requirements["namespace"])
    data["requirements"] = SnapshotRequirementsV2(**requirements)
    data["read_versions"] = tuple(GraphVersion(AtomKey.from_token(value["key"]), value["revision"])
        for value in data["read_versions"])
    result = OwnerStopReplyProjectionObservedV1(**data)
    if result.to_wire() != raw:
        raise ValueError("StopReply projection observation wire is not canonical")
    return result


def decode_owner_stop_reply_plan_v1(raw):
    if type(raw) is not dict or set(raw) != _PLAN_FIELDS or raw["schema"] != PLAN_SCHEMA:
        raise AuthorityUnavailable("closed StopReply plan fields differ")
    request = owner_stop_reply_request_from_wire_v1(raw["request"])
    scope = raw["scope"]
    if type(scope) is not dict or set(scope) != _SCOPE_FIELDS:
        raise AuthorityUnavailable("closed StopReply actual scope fields differ")
    owner_data = dict(raw["owner"])
    owner_data["namespace"] = NamespaceId(**owner_data["namespace"])
    owner = OwnerOperationBindingV1(**owner_data)
    if (scope["namespace"] != asdict(request.namespace) or owner.namespace != request.namespace
            or (scope["cycle_job_ref"], scope["c02_operation_id"]) != (request.cycle_job_ref, request.c02_operation_id)
            or type(raw["target_cancel_generation"]) is not int
            or raw["target_cancel_generation"] not in {request.expected_cancel_generation, request.expected_cancel_generation + 1}
            or type(raw["graph_snapshot"]) is not dict or set(raw["graph_snapshot"]) != {"graph_revision", "graph_epoch"}
            or any(type(value) is not int or value < 0 for value in raw["graph_snapshot"].values())
            or type(raw["child_originals"]) is not list or len(raw["child_originals"]) > 128):
        raise AuthorityUnavailable("StopReply plan initiating identity/algebra differs")
    for name in ("create_original_digest", "c02_receipt_digest"):
        if type(scope[name]) is not str or re.fullmatch("[0-9a-f]{64}", scope[name]) is None:
            raise AuthorityUnavailable("StopReply actual original commitment differs")
    if (scope["responsibility_ref"] is None) != (scope["responsibility_digest"] is None):
        raise AuthorityUnavailable("StopReply responsibility metadata is partial")
    from ..runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
    from ..runtime.d11_types import runtime_job_key
    activity, job = foreground_cycle_ids_v1(request.namespace, request.c02_operation_id)
    if (scope["cycle_job_ref"] != runtime_job_key(*request.namespace.as_tuple, activity, job).token
            or scope["create_original_ref"] != "d11-current:" + scope["create_original_digest"][:48]
            or type(scope["create_operation_id"]) is not str or not scope["create_operation_id"]
            or scope["responsibility_digest"] is not None and re.fullmatch("[0-9a-f]{64}", scope["responsibility_digest"]) is None):
        raise AuthorityUnavailable("StopReply scope is not its fixed real create/C02 locator")
    storage = raw["storage"]
    if (type(storage) is not dict or set(storage) != {"pointer_version", "manifest_digest", "storage_generation", "graph_path", "core_path", "graph_device", "graph_file_id", "graph_incarnation"}
            or any(type(storage[name]) is not int or storage[name] < 1 for name in ("pointer_version", "storage_generation"))):
        raise AuthorityUnavailable("StopReply installed C09 storage binding differs")
    seen = set()
    for item in raw["child_originals"]:
        if (type(item) is not list or len(item) != 3 or item[0] in seen
                or AtomKey.from_token(item[0]).type_name != "runtime.job"
                or NamespaceId.from_key(AtomKey.from_token(item[0])) != request.namespace
                or type(item[1]) is not str or not item[1]
                or type(item[2]) is not str or re.fullmatch("[0-9a-f]{64}", item[2]) is None):
            raise AuthorityUnavailable("StopReply child original metadata differs")
        seen.add(item[0])
    return request, owner


def require_owner_stop_reply_original_v1(original, *, request=None):
    if (type(original) is not D12BackendOperationOriginalV1 or original.kind != "control"
            or type(original.result) is not D12ControlPayloadV1 or original.result.control != "stop_reply_v1"
            or original.state not in {"cancel_requested", "pending_confirmation", "cancelled"}
            or original.result.cancellation_confirmed != (original.state == "cancelled")):
        raise AuthorityUnavailable("actual typed StopReply control original required")
    if (original.state == "cancel_requested" and original.result.domain_receipt_refs
            or original.state != "cancel_requested" and (len(original.result.domain_receipt_refs) != 1
                or not original.result.domain_receipt_refs[0].startswith("d11-current:"))):
        raise AuthorityUnavailable("StopReply state has no exact actual Graph projection reference")
    if request is not None and (original.namespace != request.namespace or original.operation_id != request.operation_id
            or original.request_digest != digest(request) or original.result.object_ref != request.cycle_job_ref):
        raise AuthorityUnavailable("StopReply original/request identity differs")
    return original


def validate_owner_stop_reply_core_row_v1(row):
    """Exact new-plan branch; old whole-Host row meanings remain untouched."""
    original = require_owner_stop_reply_original_v1(decode_original(json.loads(row[3])))
    plan = json.loads(row[7])
    request, owner = decode_owner_stop_reply_plan_v1(plan)
    require_owner_stop_reply_original_v1(original, request=request)
    scope = plan["scope"]
    refs = (("owner", owner.authority_ref, owner.authority_digest),
        ("reply_cycle_create", scope["create_original_ref"], "sha256:" + scope["create_original_digest"]),
        ("reply_cycle_c02", scope["c02_operation_id"], "sha256:" + scope["c02_receipt_digest"]))
    if scope["responsibility_ref"] is not None:
        refs += (("reply_cycle_responsibility", scope["responsibility_ref"], "sha256:" + scope["responsibility_digest"]),)
    if (row[1:3] != (original.operation_id, original.original_ref)
            or row[4] != owner.actor or owner.authority_ref != "owner-authority:" + row[6]
            or owner.grant_ref != owner_grant_key(*request.namespace.as_tuple).token
            or row[8] != scope["create_original_ref"] or row[7] != canonical_serialize(plan)
            or row[3] != canonical_serialize(asdict(original))
            or original.plan_ref != "owner-stop-plan:" + original.operation_id or original.plan_digest != digest(plan)
            or (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest, original.activation_generation)
                != (owner.grant_ref, owner.grant_revision, owner.grant_digest, owner.activation_generation)
            or original.result.effective_version != plan["target_cancel_generation"]
            or original.authority_refs != refs):
        raise AuthorityUnavailable("StopReply immutable Core row/plan/Owner binding differs")
    from .v2_owner_session import from_wire
    session = from_wire({"kind": "owner_session_login_request_v1", **json.loads(row[5])})
    if (session.authority_namespace != row[0] or session.installation_id != request.installation_id
            or _canonical(session) != row[5]):
        raise AuthorityUnavailable("StopReply Core initiating session installation differs")
    return row[0], "d12_operation_original", original.original_ref, original.operation_id


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _ActualReplyCycleScopeV1:
    service: object
    context: object
    identity: object
    activation_generation: int
    seal: object


class InstalledOwnerStopReplyServiceV1:
    def __init__(self, *, status_service, control, issuer):
        if (type(status_service) is not InstalledD12OperationStatusServiceV1
                or type(control) is not C09StorageControlV1 or type(issuer) is not D11BudgetJobIssuer
                or getattr(status_service.core, "_c09_storage_reader_v1", None) is not control
                or control.installation_id != status_service.installation_id):
            raise TypeError("StopReply requires actual same-Core installed Owner/D12/C09 services")
        self.status_service, self.control, self.issuer = status_service, control, issuer
        self.core, self.fences = status_service.core, status_service.fences
        self.namespace, self.namespace_id = status_service.namespace, status_service.namespace_id
        self.installation_id = status_service.installation_id
        self._seal = object()
        self._scopes = {}

    def _auth(self, db, *, actor, session_token, session_request):
        if session_request.installation_id != self.installation_id:
            raise AuthorityUnavailable("StopReply Owner session belongs to another installation")
        guard = self.status_service.tickets._checked_current_head(db, self.namespace)
        if guard is None:
            raise AuthorityUnavailable("StopReply current signed Owner is absent")
        return self.status_service._current_session_in_tx(db, actor=actor, token=session_token,
            request=session_request, expected_head=guard.authorization_head)

    def _storage(self):
        context = self.control.read_verified_current_storage_v1()
        context.require_current("business")
        members = {member["role"]: member for member in context.manifest["members"]}
        graph = members["graph"]
        if (Path(members["core"]["resolved_path"]) != self.core.path.resolve(strict=True)
                or Path(graph["resolved_path"]) != self.status_service._source_graphs[self.installation_id]):
            raise AuthorityUnavailable("StopReply selected actual Core/Graph differs")
        storage = {"pointer_version": context.pointer_version, "manifest_digest": context.manifest_digest,
            "storage_generation": context.storage_generation, "graph_path": graph["resolved_path"],
            "core_path": members["core"]["resolved_path"], "graph_device": graph["device"],
            "graph_file_id": graph["file_id"], "graph_incarnation": graph["incarnation_or_journal_id"]}
        return context, storage, graph

    def _metadata(self, request, *, session_request=None):
        from ..runtime.owner_stop_reply_v1 import read_plan_owner_stop_reply_v1
        from .model_reply_scope_observation_v3 import (
            _active_observation_v3, model_reply_scope_point_v3)
        observation = _active_observation_v3()
        if observation is not None and not observation.legacy:
            if observation.service is not self or not observation.db.in_transaction:
                raise AuthorityUnavailable("StopReply metadata lost its actual observing service/transaction")
            db = observation.db
            metadata = read_plan_owner_stop_reply_v1(db, namespace=self.namespace_id,
                request=request, issuer=self.issuer)
            row = model_reply_scope_point_v3(db, table='graph_recovery_metadata_v2',
                columns=('requirements_json',), key_columns=('bot', 'persona'), key=self.namespace_id.as_tuple,
                legacy_reader=lambda: db.execute(
                    "SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    self.namespace_id.as_tuple).fetchone())
            from ..runtime.domain_background_read_v3 import background_json_loads_v3
            requirements = background_json_loads_v3(row[0])
            storage = observation.storage
            if (requirements["authority_id"] != self.control.authority_id
                    or requirements["authority_namespace"] != self.namespace
                    or requirements["graph_incarnation"] != storage["graph_incarnation"]):
                raise AuthorityUnavailable("StopReply actual Graph recovery identity differs")
            owner_grant = self._owner_grant_v1(db, session_request)
            return observation.context, storage, metadata, owner_grant, requirements["activation_generation"]
        context, storage, graph = self._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            metadata = read_plan_owner_stop_reply_v1(db, namespace=self.namespace_id, request=request, issuer=self.issuer)
            requirements = json.loads(db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                self.namespace_id.as_tuple).fetchone()[0])
            if (requirements["authority_id"] != self.control.authority_id
                    or requirements["authority_namespace"] != self.namespace
                    or requirements["graph_incarnation"] != storage["graph_incarnation"]):
                raise AuthorityUnavailable("StopReply actual Graph recovery identity differs")
            owner_grant = self._owner_grant_v1(db, session_request)
        self.control.verify_member_v1(graph, prepared=False)
        context.require_current("business")
        return context, storage, metadata, owner_grant, requirements["activation_generation"]

    def _owner_grant_v1(self, db, session_request):
        grant_key = owner_grant_key(*self.namespace_id.as_tuple)
        from .model_reply_scope_observation_v3 import model_reply_scope_point_v3
        from ..runtime.domain_background_read_v3 import background_json_loads_v3
        grant = model_reply_scope_point_v3(db, table='graph_atoms',
            columns=('revision', 'value', 'valid'), key_columns=('token',), key=(grant_key.token,),
            legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (grant_key.token,)).fetchone())
        if grant is None or grant[2] != 1:
            raise AuthorityUnavailable("StopReply current Owner grant is absent")
        value = background_json_loads_v3(grant[1])
        if session_request is not None and ("workbench.control" not in value["capabilities"]
                or "workbench_user_action" not in value["purposes"] or "owner" not in value["audiences"]
                or value["principal"] != asdict(session_request.principal)):
            raise AuthorityUnavailable("StopReply current Owner control scope is unavailable")
        return grant_key.token, grant[0], digest(value)

    def _rows(self, db):
        return tuple(db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? ORDER BY rowid", (self.namespace,)))

    def _scope_row(self, db, identity):
        for row in self._rows(db):
            plan = json.loads(row[7])
            if plan.get("schema") != PLAN_SCHEMA:
                continue
            validate_owner_stop_reply_core_row_v1(row)
            if plan["scope"] == asdict(identity):
                return row
        return None

    def submit_owner_stop_reply_v1(self, *, credential, subject, request, actor, session_token, session_request):
        from .mtls_server import MtlsPeerCredential
        if type(credential) is not MtlsPeerCredential or subject != "mtls:sha256:" + credential.certificate_sha256:
            raise AuthorityUnavailable("StopReply requires its protected actual mTLS caller identity")
        if type(request) is not OwnerStopReplyRequestV1 or (request.namespace, request.installation_id) != (self.namespace_id, self.installation_id):
            raise AuthorityUnavailable("StopReply request crossed its actual installation scope")
        self.core._require(credential, "d12_operation_status", self.namespace)
        with self.core._tx() as db:
            guard = self._auth(db, actor=actor, session_token=session_token, session_request=session_request)
            active = tuple(db.execute("SELECT * FROM authority_v2_fences WHERE namespace=? AND state='active'", (self.namespace,)))
        context, storage, metadata, grant, generation = self._metadata(request, session_request=session_request)
        with self.fences._frozen() as (db, deletion, execution, _):
            current_guard = self._auth(db, actor=actor, session_token=session_token, session_request=session_request)
            anchor = self.fences._current_locked(db, deletion, execution, require_clear=False, require_no_pending=False)
            context.require_current("business")
            if (current_guard != guard or anchor.activation_generation != generation
                    or tuple(db.execute("SELECT * FROM authority_v2_fences WHERE namespace=? AND state='active'", (self.namespace,))) != active):
                raise AuthorityUnavailable("StopReply Owner/activation/active original changed during observation")
            existing_operation = tuple(row for row in self._rows(db) if row[1] == request.operation_id)
            if existing_operation:
                row = existing_operation[0]
                validate_owner_stop_reply_core_row_v1(row)
                if decode_original(json.loads(row[3])).request_digest != digest(request):
                    raise AuthorityUnavailable("StopReply UUID was reused with another request")
                return self.status_service._authenticate_original_row_in_tx(db, row, actor=actor, token=session_token, request=session_request)
            existing = self._scope_row(db, metadata.identity)
            if existing is not None:
                return self.status_service._authenticate_original_row_in_tx(db, existing, actor=actor, token=session_token, request=session_request)
            if metadata.expected_cancel_generation != request.expected_cancel_generation:
                raise AuthorityUnavailable("StopReply UI cancellation generation is stale")
            repeated = self._metadata(request, session_request=session_request)
            if (repeated[1], repeated[2], repeated[3], repeated[4]) != (storage, metadata, grant, generation):
                raise AuthorityUnavailable("StopReply pinned target/Owner metadata changed before acceptance")
            owner = OwnerOperationBindingV1(self.namespace_id, actor, generation, *grant,
                "owner-authority:" + guard.authorization_head, digest(guard))
            plan = {"schema": PLAN_SCHEMA, "request": request.to_wire(), "scope": asdict(metadata.identity),
                "owner": asdict(owner), "storage": storage,
                "graph_snapshot": {"graph_revision": metadata.graph_revision, "graph_epoch": metadata.graph_epoch},
                "child_originals": [list(item) for item in metadata.child_originals],
                "target_cancel_generation": metadata.target_cancel_generation}
            decode_owner_stop_reply_plan_v1(plan)
            payload = D12ControlPayloadV1(request.cycle_job_ref, "stop_reply_v1", metadata.target_cancel_generation, (), False)
            refs = (("owner", owner.authority_ref, owner.authority_digest),
                ("reply_cycle_create", metadata.identity.create_original_ref, "sha256:" + metadata.identity.create_original_digest),
                ("reply_cycle_c02", metadata.identity.c02_operation_id, "sha256:" + metadata.identity.c02_receipt_digest))
            if metadata.identity.responsibility_ref is not None:
                refs += (("reply_cycle_responsibility", metadata.identity.responsibility_ref,
                    "sha256:" + metadata.identity.responsibility_digest),)
            material = dict(schema=SCHEMA, kind="control", namespace=self.namespace_id, operation_id=request.operation_id,
                request_digest=digest(request), plan_ref="owner-stop-plan:" + request.operation_id, plan_digest=digest(plan),
                activation_generation=generation, owner_grant_ref=grant[0], owner_grant_revision=grant[1], owner_grant_digest=grant[2],
                authority_refs=refs,
                state="cancel_requested", coverage=("durable_reply_scope_barrier",), missing_inputs=(), result=payload,
                result_digest=digest(payload), original_ref="owner-stop-request:" + request.operation_id)
            material["original_digest"] = backend_original_digest_v1(material)
            original = self.status_service._readdress(D12BackendOperationOriginalV1(**material))
            row = (self.namespace, request.operation_id, original.original_ref, canonical_serialize(asdict(original)),
                actor, _canonical(session_request), guard.authorization_head, canonical_serialize(plan), metadata.identity.create_original_ref)
            validate_owner_stop_reply_core_row_v1(row)
            db.execute("INSERT INTO authority_d12_operation_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)", row)
            return original

    def read_owner_stop_reply_status_v1(self, *, credential, actor, session_token, session_request, original_ref):
        self.core._require(credential, "d12_operation_status", self.namespace)
        with self.core._tx() as db:
            row = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND original_ref=?",
                (self.namespace, original_ref)).fetchone()
            if row is None:
                raise AuthorityUnavailable("StopReply original is absent")
            validate_owner_stop_reply_core_row_v1(row)
            original = self.status_service._authenticate_original_row_in_tx(db, row, actor=actor, token=session_token, request=session_request)
            projected = self.read_status_original_in_tx_v1(db, source_row=row, original=original)
            return self.status_service.persist_derived_original_in_tx_v1(db, source_row=row, original=projected)

    def _projection_owner_in_tx_v1(self, db, row):
        from .v2_owner_session import from_wire
        session = from_wire({"kind": "owner_session_login_request_v1", **json.loads(row[5])})
        sessions = self.status_service.sessions
        sessions._current_key(db, session)
        source = sessions._current_pairing_source
        if source is None:
            raise AuthorityUnavailable("StopReply projection current Owner pairing is absent")
        source.require_current_actor_in_tx(db, authority_namespace=self.namespace,
            installation_id=self.installation_id, actor_id=row[4], principal=session.principal)
        guard = self.status_service.tickets._checked_current_head(db, self.namespace)
        if (guard is None or guard.authorization_head != row[6] or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision or guard.minimum_revocation_epoch):
            raise AuthorityUnavailable("StopReply initiating Owner changed before metadata projection")
        return session, guard

    def read_owner_stop_reply_projection_v1(self, *, credential, original_ref):
        """Protected Host metadata read; the DTO is not an Owner write lease.

        The consumer additionally binds its fixed cancellation witness to a real
        current write fence. No browser bearer is stored or renewed here.
        """
        self.core._require(credential, "d12_operation_status", self.namespace)
        with self.core._tx() as db:
            row = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND original_ref=?",
                (self.namespace, original_ref)).fetchone()
            if row is None:
                raise AuthorityUnavailable("StopReply projection original is absent")
            validate_owner_stop_reply_core_row_v1(row)
            plan = json.loads(row[7])
            request = owner_stop_reply_request_from_wire_v1(plan["request"])
            accepted = self._scope_row(db, self._identity_from_plan_v1(plan))
            if accepted is None:
                raise AuthorityUnavailable("StopReply immutable accepted intent is absent")
            original = decode_original(json.loads(accepted[3]))
            if original.state != "cancel_requested":
                raise AuthorityUnavailable("StopReply projection requires the initial immutable intent")
            session, guard = self._projection_owner_in_tx_v1(db, accepted)
        context, _, metadata, grant, generation = self._metadata(request, session_request=session)
        with self.core._tx() as db:
            again, current_guard = self._projection_owner_in_tx_v1(db, accepted)
            context.require_current("business")
            if (again != session or current_guard != guard or generation != original.activation_generation
                    or self.core._row(db, self.namespace)[1] != generation
                    or grant != (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest)
                    or asdict(metadata.identity) != plan["scope"]):
                raise AuthorityUnavailable("StopReply current projection qualification changed; intent remains pending")
        return request, original

    def observe_owner_stop_reply_projection_v1(self, *, credential, subject, permit, original_ref):
        """Observe only the fixed metadata projection under a real write fence.

        Graph/C09 file observations finish before the final frozen Core section.
        The Host must keep this paired response in its private witness custody.
        """
        from .mtls_server import MtlsPeerCredential
        from ..graph_store import GraphStore
        from ..runtime.owner_stop_reply_v1 import read_plan_owner_stop_reply_v1
        from ..runtime.d11_types import job_graph_write
        if (self.core._db.in_transaction or type(credential) is not MtlsPeerCredential
                or subject != "mtls:sha256:" + credential.certificate_sha256
                or type(permit) is not FencePermitV2 or permit.operation != "write"):
            raise AuthorityUnavailable("StopReply projection observation needs its outside-SQL actual paired write permit")
        self.fences._require_permit(credential=credential, subject=subject, permit=permit)
        self.fences.validate_fence(credential=credential, subject=subject, permit=permit)
        with self.core._tx() as db:
            row = db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE authority_namespace=? AND original_ref=?",
                (self.namespace, original_ref)).fetchone()
            if row is None:
                raise AuthorityUnavailable("StopReply projection initial intent is absent")
            validate_owner_stop_reply_core_row_v1(row)
            plan = json.loads(row[7])
            request = owner_stop_reply_request_from_wire_v1(plan["request"])
            accepted_row = self._scope_row(db, self._identity_from_plan_v1(plan))
            initial = decode_original(json.loads(accepted_row[3]))
            if (initial.state != "cancel_requested" or initial.original_ref != original_ref
                    or permit.operation_id != "owner-stop-projection:" + initial.operation_id
                    or permit.generation != initial.activation_generation):
                raise AuthorityUnavailable("StopReply projection permit does not bind the exact initial intent")
            session, guard = self._projection_owner_in_tx_v1(db, accepted_row)
        context, storage, member = self._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri() + "?mode=ro", uri=True)) as graph:
            graph.execute("PRAGMA query_only=ON")
            graph.execute("BEGIN")
            metadata = read_plan_owner_stop_reply_v1(graph, namespace=self.namespace_id,
                request=request, issuer=self.issuer)
            recovery = GraphStore._decode_recovery(graph.execute("SELECT schema,requirements_json,graph_revision "
                "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", self.namespace_id.as_tuple).fetchone(), self.namespace_id)
            if recovery is None or asdict(metadata.identity) != plan["scope"]:
                raise AuthorityUnavailable("StopReply projection actual selected Graph/create stamp differs")
            requirements = recovery.requirements
            anchor = permit.pinned_anchor
            if ((requirements.authority_id, requirements.authority_namespace, requirements.activation_generation,
                    requirements.deletion_journal_id, requirements.deletion_seq, requirements.deletion_digest,
                    requirements.execution_journal_id, requirements.execution_seq, requirements.execution_digest,
                    requirements.revocation_epoch, requirements.graph_incarnation)
                    != (anchor.authority_id, anchor.namespace, anchor.activation_generation,
                        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
                        anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest,
                        anchor.revocation_epoch, storage["graph_incarnation"])):
                raise AuthorityUnavailable("StopReply projection Graph requires actual current recovery before a metadata write")
            grant = self._owner_grant_v1(graph, session)
            if grant != (initial.owner_grant_ref, initial.owner_grant_revision, initial.owner_grant_digest):
                raise AuthorityUnavailable("StopReply projection actual current Owner grant changed")
            versions = [GraphVersion(AtomKey.from_token(grant[0]), grant[1])]
            for job in metadata.jobs:
                projection = job_graph_write(job)
                atom = graph.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                    (*self.namespace_id.as_tuple, projection.key.token)).fetchone()
                if atom is None or atom[1:] != (canonical_serialize(projection.value), 1):
                    raise AuthorityUnavailable("StopReply projection actual job SQL/Graph metadata differs")
                versions.append(GraphVersion(projection.key, atom[0]))
        self.control.verify_member_v1(member, prepared=False)
        context.require_current("business")
        with self.fences._frozen() as (db, deletion, execution, _):
            actual_anchor = self.fences._current_locked(db, deletion, execution,
                holder=permit.holder, generation=permit.generation)
            current_session, current_guard = self._projection_owner_in_tx_v1(db, accepted_row)
            if (current_session != session or current_guard != guard or actual_anchor != permit.pinned_anchor
                    or db.execute("SELECT * FROM authority_d12_operation_originals_v1 WHERE original_ref=?",
                        (initial.original_ref,)).fetchone() != accepted_row):
                raise AuthorityUnavailable("StopReply projection Core/Owner original changed before observation")
            self.fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=actual_anchor)
            self._require_projection_pointer_in_tx_v1(db, context)
            self._require_reply_retirement_ledger_in_tx_v1(db, c02_operation_id=request.c02_operation_id)
        return OwnerStopReplyProjectionObservedV1(request, initial, permit, accepted_row[4], guard,
            grant[0], grant[1], grant[2][7:], requirements, metadata.graph_revision, metadata.graph_epoch,
            tuple(versions), context.pointer_version, context.storage_generation, canonical_digest(storage))

    def _require_projection_pointer_in_tx_v1(self, db, context):
        # This is the installed source-location qualifier's narrow pointer check;
        # business/applied Graph originals were observed before acquiring Core.
        if (db is not self.core._db or not db.in_transaction or context._reader is not self.control
                or context._capability is not self.control._capability
                or getattr(self.core, "_c09_storage_reader_v1", None) is not self.control):
            raise AuthorityUnavailable("projection pointer requires actual same-Core installed C09 context")
        with self.control._db() as control_db:
            current = self.control._current(control_db)
            if (current["pointer_version"], current["current_manifest_digest"], current["stage"]) != (
                    context.pointer_version, context.manifest_digest, context.stage):
                raise AuthorityUnavailable("StopReply projection selected pointer changed")

    @staticmethod
    def _identity_from_plan_v1(plan):
        from ..runtime.owner_stop_reply_v1 import OwnerReplyCycleIdentityV1
        scope = dict(plan["scope"])
        scope["namespace"] = NamespaceId(**scope["namespace"])
        return OwnerReplyCycleIdentityV1(**scope)

    def read_status_original_in_tx_v1(self, db, *, source_row, original):
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("StopReply status needs its actual same-Core transaction")
        validate_owner_stop_reply_core_row_v1(source_row)
        plan = json.loads(source_row[7])
        request = owner_stop_reply_request_from_wire_v1(plan["request"])
        from .v2_owner_session import from_wire
        source_session = from_wire({"kind": "owner_session_login_request_v1", **json.loads(source_row[5])})
        _, storage, metadata, _, _ = self._metadata(request, session_request=source_session)
        if asdict(metadata.identity) != plan["scope"]:
            raise AuthorityUnavailable("StopReply status target create identity changed")
        cycle = metadata.jobs[0]
        if cycle.cancel_epoch < original.result.effective_version:
            return original
        from ..runtime.owner_stop_reply_v1 import read_original_owner_stop_reply_projection_v1
        accepted_row = self._scope_row(db, metadata.identity)
        accepted = decode_original(json.loads(accepted_row[3]))
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri() + "?mode=ro", uri=True)) as graph:
            graph.execute("BEGIN")
            projection_ref = read_original_owner_stop_reply_projection_v1(graph, namespace=self.namespace_id, original=accepted)
        if projection_ref is None:
            return accepted
        confirmed = not metadata.pending_effect_refs and all(job.phase in {"completed", "failed", "cancelled"}
            and job.lease_holder is None for job in metadata.jobs)
        payload = replace(original.result, cancellation_confirmed=confirmed, domain_receipt_refs=(projection_ref,))
        material = {field.name: getattr(original, field.name) for field in fields(original)}
        material.update(state="cancelled" if confirmed else "pending_confirmation", result=payload,
            result_digest=digest(payload), coverage=("durable_reply_scope_barrier", "actual_graph_cancellation_projection"))
        material["original_digest"] = backend_original_digest_v1(material)
        return D12BackendOperationOriginalV1(**material)

    def observe_actual_reply_scope_v1(self, *, c02_operation_id):
        """Called by an installed typed verifier before its final Core admission."""
        if self.core._db.in_transaction:
            raise AuthorityUnavailable("StopReply scope observation must precede the final Core transaction")
        from ..runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
        from ..runtime.d11_types import runtime_job_key
        from uuid import uuid4
        activity, job = foreground_cycle_ids_v1(self.namespace_id, c02_operation_id)
        self.require_reply_cycle_not_retired_v1(c02_operation_id=c02_operation_id)
        request = OwnerStopReplyRequestV1(self.namespace_id, self.installation_id, str(uuid4()),
            runtime_job_key(*self.namespace_id.as_tuple, activity, job).token, c02_operation_id, 0)
        from .model_reply_scope_observation_v3 import _active_observation_v3
        observation = _active_observation_v3()
        if observation is not None and not observation.legacy:
            if observation.service is not self:
                raise AuthorityUnavailable("StopReply scope crossed its actual observing service")
            if observation.issued_scope is not None:
                raise AuthorityUnavailable("StopReply scope already issued in this model observation")
            context, _, metadata, _, generation = observation.evaluate_v3(
                lambda db: self._metadata(request))
            self.control.verify_member_v1(observation.member, prepared=False)
            context.require_current("business")
            self.require_reply_cycle_not_retired_v1(c02_operation_id=c02_operation_id)
        else:
            context, _, metadata, _, generation = self._metadata(request)
        value = _ActualReplyCycleScopeV1(self, context, metadata.identity, generation, self._seal)
        key = id(value)
        self._scopes[key] = weakref.ref(value, lambda _: self._scopes.pop(key, None))
        if observation is not None and not observation.legacy:
            observation.issued_scope = value
        return value

    def require_reply_cycle_not_retired_v1(self, *, c02_operation_id):
        """Deny-only early check, including an absent Graph create target.

        Absence is not a positive scope observation. The caller must still run
        its actual installed C02/create/Source/Owner qualification.
        """
        if self.core._db.in_transaction:
            raise AuthorityUnavailable("reply retirement observation must precede the admission transaction")
        context, _, _ = self._storage()
        with self.core._tx() as db:
            self.require_reply_cycle_not_retired_in_tx_v1(db, context=context, c02_operation_id=c02_operation_id)

    def require_reply_cycle_not_retired_in_tx_v1(self, db, *, context, c02_operation_id):
        if (db is not self.core._db or not db.in_transaction or context._reader is not self.control
                or context._capability is not self.control._capability):
            raise AuthorityUnavailable("reply retirement requires the actual selected Core/C09 transaction")
        context.require_current("business")
        self._require_reply_retirement_ledger_in_tx_v1(db, c02_operation_id=c02_operation_id)

    def _require_reply_retirement_ledger_in_tx_v1(self, db, *, c02_operation_id):
        from ..runtime.foreground_cycle_v1 import foreground_cycle_ids_v1
        from ..runtime.d11_types import runtime_job_key
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("retirement ledger lookup requires the actual final Core transaction")
        activity, job_id = foreground_cycle_ids_v1(self.namespace_id, c02_operation_id)
        key = runtime_job_key(*self.namespace_id.as_tuple, activity, job_id)
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone()
        if exists is None:
            return
        columns = tuple(row[1] for row in db.execute("PRAGMA table_info(authority_c09_consumed_execution_v1)"))
        if columns != _CONSUMED_COLUMNS:
            raise AuthorityUnavailable("actual C09 reply retirement ledger columns differ")
        retired = db.execute("SELECT operation_id,original_commitment,facts_pin_digest FROM authority_c09_consumed_execution_v1 "
            "WHERE namespace=? AND kind=? AND item_id=?", (self.namespace, _RETIREMENT_KIND, key.name)).fetchone()
        if retired is None:
            return
        operation, commitment, pin = retired
        try:
            expected = owner_reply_cycle_retirement_commitment_v1(self.namespace, key.token, operation)
        except ValueError as exc:
            raise AuthorityUnavailable("C09 stable reply retirement UUID differs; HOLD") from exc
        if (commitment != expected
                or type(pin) is not str or re.fullmatch("[0-9a-f]{64}", pin) is None):
            raise AuthorityUnavailable("C09 stable reply retirement commitment/pin differs; HOLD")
        originals = tuple(db.execute("SELECT item_id,original_commitment FROM authority_c09_consumed_execution_v1 "
            "WHERE namespace=? AND kind='d12_operation_original' AND operation_id=? AND facts_pin_digest=?",
            (self.namespace, operation, pin)))
        sources = tuple(db.execute("SELECT item_id,original_commitment FROM authority_c09_consumed_execution_v1 "
            "WHERE namespace=? AND kind='d12_source_original' AND operation_id=? AND facts_pin_digest=?",
            (self.namespace, operation, pin)))
        if (not originals or any(re.fullmatch("d12authority:[0-9a-f]{64}", item) is None
                or re.fullmatch("[0-9a-f]{64}", digest_value) is None for item, digest_value in originals)
                or len(sources) != 1 or re.fullmatch("d11-current:[0-9a-f]{48}", sources[0][0]) is None):
            raise AuthorityUnavailable("C09 reply retirement has no complete actual D12 original/source group; HOLD")
        source_ref, source_commitment = sources[0]
        from .c09_authority_storage_rebase import _digest as c09_digest
        if source_commitment != c09_digest((self.namespace, operation, source_ref)):
            raise AuthorityUnavailable("C09 reply retirement actual source tuple differs; HOLD")
        raise AuthorityUnavailable("Owner reply cycle was retired by actual C09; new work is denied")

    def list_owner_reply_controls_v1(self, *, credential, actor, session_token, session_request, cursor=None, subject=None):
        self.core._require(credential, "d12_operation_status", self.namespace)
        with self.core._tx() as db:
            guard = self._auth(db, actor=actor, session_token=session_token, session_request=session_request)
        context, storage, _ = self._storage()
        with closing(sqlite3.connect(Path(storage["graph_path"]).as_uri() + "?mode=ro", uri=True)) as graph:
            graph.execute("BEGIN")
            self._owner_grant_v1(graph, session_request)
            targets, next_cursor = _read_owner_reply_control_targets_v1(graph, self.namespace_id, cursor)
        from ..runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1, foreground_cycle_ids_v1
        from ..runtime.d11_types import runtime_job_key
        from uuid import uuid4
        result = []
        for _, encoded in targets:
            c02 = foreground_cycle_from_wire_v1(json.loads(encoded)).c02_operation_id
            activity, job = foreground_cycle_ids_v1(self.namespace_id, c02)
            request = OwnerStopReplyRequestV1(self.namespace_id, self.installation_id, str(uuid4()),
                runtime_job_key(*self.namespace_id.as_tuple, activity, job).token, c02, 0)
            _, _, metadata, _, _ = self._metadata(request, session_request=session_request)
            with self.core._tx() as db:
                current = self._auth(db, actor=actor, session_token=session_token, session_request=session_request)
                if current != guard:
                    raise AuthorityUnavailable("StopReply Owner changed during metadata listing")
                row = self._scope_row(db, metadata.identity)
                original = None if row is None else self.status_service._authenticate_original_row_in_tx(db, row,
                    actor=actor, token=session_token, request=session_request)
                if original is not None:
                    projected = self.read_status_original_in_tx_v1(db, source_row=row, original=original)
                    original = self.status_service.persist_derived_original_in_tx_v1(db, source_row=row, original=projected)
            projection=self.natural_disposition_maintenance.project_owner_metadata_v1(credential=credential,subject=subject,parent_original_id=c02)
            result.append(OwnerReplyControlMetadataV2(self.namespace_id, self.installation_id, request.cycle_job_ref,
                c02, metadata.expected_cancel_generation, metadata.jobs[0].phase,
                None if original is None else original.original_ref, None if original is None else original.state,
                natural_batch=projection.to_wire()))
        with self.core._tx() as db:
            current = self._auth(db, actor=actor, session_token=session_token, session_request=session_request)
            if current != guard:
                raise AuthorityUnavailable("StopReply Owner changed before metadata disclosure")
            context.require_current("business")
        return OwnerReplyControlPageV1(tuple(result), next_cursor)


def read_original_parent_reply_stop_v1(core_db, *, actual_cycle_identity):
    scope = actual_cycle_identity
    if (type(scope) is not _ActualReplyCycleScopeV1 or scope.seal is not scope.service._seal
            or scope.service._scopes.get(id(scope), lambda: None)() is not scope
            or core_db is not scope.service.core._db or not core_db.in_transaction):
        raise AuthorityUnavailable("actual installed reply scope observation and final Core transaction required")
    scope.context.require_current("business")
    row = scope.service._scope_row(core_db, scope.identity)
    return None if row is None else decode_original(json.loads(row[3]))


def require_reply_scope_not_stopped_in_tx_v1(core_db, *, authority_namespace, installation_id,
        activation_generation, actual_cycle_identity, action):
    if action not in _STOP_ACTIONS:
        raise AuthorityUnavailable("StopReply barrier is only for registered new-work admissions")
    scope = actual_cycle_identity
    if (type(scope) is not _ActualReplyCycleScopeV1
            or (scope.service.namespace, scope.service.installation_id, scope.activation_generation)
                != (authority_namespace, installation_id, activation_generation)):
        raise AuthorityUnavailable("StopReply admission scope crossed its installed identity")
    original = read_original_parent_reply_stop_v1(core_db, actual_cycle_identity=scope)
    scope.service.require_reply_cycle_not_retired_in_tx_v1(core_db, context=scope.context,
        c02_operation_id=scope.identity.c02_operation_id)
    if scope.service.core._row(core_db, authority_namespace)[1] != activation_generation:
        raise AuthorityUnavailable("StopReply admission activation changed")
    if original is not None:
        raise AuthorityUnavailable("Owner StopReply is durably accepted; new reply-scope work is denied")
