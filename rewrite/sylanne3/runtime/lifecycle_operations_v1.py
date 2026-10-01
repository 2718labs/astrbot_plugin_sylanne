"""Installed D12 producers using W01's database and current Owner fences.

Construction is an administrator operation. ``owner_command_fence`` must yield
an OwnerOperationBindingV1 only after checking the signed session, graph grant,
Authority Owner guard, current generation and requested capability. The separate
``owner_status_fence`` authenticates that same Owner and an *exact operation*
without admitting content from a revoked source. Neither callback is accepted
from a workbench request. Install the schema before opening any content fence.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
import json
import re
from threading import RLock
from typing import Callable, Mapping
from uuid import UUID

from ..contracts import StaleRead
from ..domains.d12.backend_operation_contracts_v1 import (
    SCHEMA, D12BackendOperationOriginalV1, D12ControlPayloadV1,
    D12MaintenancePayloadV1, D12TransferExecutionPayloadV1,
    D12TransferPlanPayloadV1, D12ExperimentPayloadV1, D12SupportExportPayloadV1,
    backend_original_digest_v1,
)
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from ..authority_service.v2_migration_contract import (
    MigrationPlanV2, MigrationRecoveryV2, SourceSnapshotReceiptV2,
    TargetRecoveryReceiptV2,
)
from .restore_anchor import RestoreAnchor
from .jobs import cancel_job, get_job

TABLES = ("graph_d12_backend_operations_v1", "graph_d12_backend_originals_v1",
          "graph_d12_lifecycle_plans_v1", "graph_d12_lifecycle_steps_v1")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


class D12PrerequisiteUnavailable(LookupError):
    """An installed prerequisite is missing before any operation is admitted."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class D12OperationPending(RuntimeError):
    def __init__(self, original):
        self.original = original
        super().__init__("original_operation_continuation_required")


def digest(value: object) -> str:
    return "sha256:" + canonical_digest(value)


def _json(value: object) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True, slots=True)
class OwnerOperationBindingV1:
    namespace: NamespaceId
    actor: str
    activation_generation: int
    grant_ref: str
    grant_revision: int
    grant_digest: str
    authority_ref: str
    authority_digest: str

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId:
            raise TypeError("current Owner namespace required")
        if any(type(v) is not str or not v for v in
               (self.actor, self.grant_ref, self.authority_ref)):
            raise ValueError("current Owner identities required")
        if any(type(v) is not int or v < 1 for v in
               (self.activation_generation, self.grant_revision)):
            raise ValueError("current Owner versions required")
        if any(_SHA.fullmatch(v) is None for v in
               (self.grant_digest, self.authority_digest)):
            raise ValueError("current Owner digests required")


@dataclass(frozen=True, slots=True)
class ResolvedTransferPlanV1:
    """Current registry resolution; includes both ends, never a browser plan."""
    payload: D12TransferPlanPayloadV1
    migration_plan: MigrationPlanV2 | None
    target_authority_namespace: str
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    policy_ref: str
    policy_digest: str
    target_lease_ref: str | None = None

    def __post_init__(self):
        if type(self.payload) is not D12TransferPlanPayloadV1:
            raise TypeError("typed resolved transfer payload required")
        if self.target_authority_namespace != self.payload.authority_namespace:
            raise ValueError("v1 cannot transfer across Authorities")
        if any(type(v) is not int or v < 0 for v in
               (self.graph_revision, self.access_epoch, self.delete_epoch)):
            raise ValueError("current source epochs required")
        if not self.policy_ref or _SHA.fullmatch(self.policy_digest) is None:
            raise ValueError("installed transfer policy original required")
        if self.target_lease_ref is not None and (type(self.target_lease_ref) is not str or not self.target_lease_ref):
            raise ValueError("opaque installed target lease required")
        if self.payload.mode == "relocate":
            plan = self.migration_plan
            if (type(plan) is not MigrationPlanV2 or
                    (plan.namespace, plan.source_installation_id,
                     plan.target_installation_id) !=
                    (self.payload.authority_namespace,
                     self.payload.source_installation_id,
                     self.payload.target_installation_id)):
                raise ValueError("paired migration plan differs from resolved ends")


@dataclass(frozen=True, slots=True)
class ControlCommandV1:
    object_ref: str
    control: str
    config_diff: Mapping[str, object]
    test_intent: Mapping[str, object] | None

    @classmethod
    def from_wire(cls, data: Mapping[str, object]):
        if set(data) != {"object_ref", "control", "config_diff", "test_intent"}:
            raise ValueError("control fields differ")
        if any(type(data[k]) is not str or not data[k] or len(data[k]) > 4096
               for k in ("object_ref", "control")):
            raise ValueError("bounded control selectors required")
        if type(data["config_diff"]) is not dict or type(data["test_intent"]) not in (dict, type(None)):
            raise ValueError("typed control configuration required")
        if len(_json(data).encode()) > 65536:
            raise ValueError("control exceeds bounded contract")
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ControlCommitV1:
    payload: D12ControlPayloadV1
    state: str
    authority_refs: tuple[tuple[str, str, str], ...]
    coverage: tuple[str, ...]
    missing_inputs: tuple[str, ...] = ()


def decode_original(data: Mapping[str, object]) -> D12BackendOperationOriginalV1:
    values = dict(data)
    values["namespace"] = NamespaceId(**values["namespace"])
    payload = dict(values["result"])
    kind = values["kind"]
    if kind == "transfer_plan":
        requirements = dict(payload["snapshot_requirements"])
        requirements["namespace"] = NamespaceId(**requirements["namespace"])
        payload["snapshot_requirements"] = SnapshotRequirementsV2(**requirements)
        payload["loss_coverage"] = tuple(payload["loss_coverage"])
        values["result"] = D12TransferPlanPayloadV1(**payload)
    elif kind == "transfer_execution":
        values["result"] = D12TransferExecutionPayloadV1(**payload)
    elif kind == "control":
        payload["domain_receipt_refs"] = tuple(payload["domain_receipt_refs"])
        values["result"] = D12ControlPayloadV1(**payload)
    elif kind == "maintenance":
        payload["stage_receipt_refs"] = tuple(payload["stage_receipt_refs"])
        values["result"] = D12MaintenancePayloadV1(**payload)
    elif kind == "experiment":
        payload["sandbox_namespace"] = NamespaceId(**payload["sandbox_namespace"])
        values["result"] = D12ExperimentPayloadV1(**payload)
    elif kind == "support_export":
        for key in ("allowed_data", "coverage"):
            payload[key] = tuple(payload[key])
        values["result"] = D12SupportExportPayloadV1(**payload)
    else:
        raise ValueError("unsupported lifecycle original kind")
    for key in ("coverage", "missing_inputs"):
        values[key] = tuple(values[key])
    values["authority_refs"] = tuple(tuple(item) for item in values["authority_refs"])
    return D12BackendOperationOriginalV1(**values)


class LifecycleOriginalStoreV1:
    """Namespace-owned originals in the existing shared business connection."""
    def __init__(self, *, db, lock):
        self.db, self.lock = db, lock

    def install_schema(self):
        with self.lock:
            if self.db.in_transaction:
                raise RuntimeError("install lifecycle schema before runtime fences")
            for sql in (
                "CREATE TABLE IF NOT EXISTS graph_d12_backend_operations_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,kind TEXT NOT NULL,owner_json TEXT NOT NULL,input_json TEXT NOT NULL,current_original_ref TEXT,PRIMARY KEY(bot,persona,operation_id))",
                "CREATE TABLE IF NOT EXISTS graph_d12_backend_originals_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,operation_id TEXT NOT NULL,original_digest TEXT NOT NULL,original_json TEXT NOT NULL,PRIMARY KEY(bot,persona,original_ref))",
                "CREATE TABLE IF NOT EXISTS graph_d12_lifecycle_plans_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,plan_ref TEXT NOT NULL,plan_digest TEXT NOT NULL,plan_json TEXT NOT NULL,PRIMARY KEY(bot,persona,plan_ref))",
                "CREATE TABLE IF NOT EXISTS graph_d12_lifecycle_steps_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,stage TEXT NOT NULL,intent_digest TEXT NOT NULL,receipt_json TEXT,PRIMARY KEY(bot,persona,operation_id,stage))",
            ):
                self.db.execute(sql)

    @contextmanager
    def transaction(self):
        with self.lock:
            if self.db.in_transaction:
                raise RuntimeError("lifecycle requires its own W01 transaction")
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def get_operation(self, namespace, operation_id):
        return self.db.execute("SELECT request_digest,kind,owner_json,input_json,current_original_ref FROM graph_d12_backend_operations_v1 WHERE bot=? AND persona=? AND operation_id=?",
                               (*namespace.as_tuple, operation_id)).fetchone()

    def claim(self, owner, operation_id, request_digest, kind, input_data):
        parsed = UUID(operation_id)
        if parsed.version != 4 or str(parsed) != operation_id or _SHA.fullmatch(request_digest) is None:
            raise ValueError("canonical operation UUID4 and request digest required")
        prior = self.get_operation(owner.namespace, operation_id)
        expected = (request_digest, kind, _json(owner), _json(input_data))
        if prior is not None:
            if prior[:4] != expected:
                raise StaleRead("operation ID is bound to another request or Owner")
            return prior
        self.db.execute("INSERT INTO graph_d12_backend_operations_v1 VALUES(?,?,?,?,?,?,?,NULL)",
                        (*owner.namespace.as_tuple, operation_id, *expected))
        return None

    def original(self, namespace, original_ref):
        row = self.db.execute("SELECT original_digest,original_json FROM graph_d12_backend_originals_v1 WHERE bot=? AND persona=? AND original_ref=?",
                              (*namespace.as_tuple, original_ref)).fetchone()
        if row is None:
            raise LookupError("backend operation original absent")
        value = decode_original(json.loads(row[1]))
        if value.original_ref != original_ref or value.namespace != namespace or value.original_digest != row[0]:
            raise ValueError("durable lifecycle original differs")
        return value

    def publish(self, owner, operation_id, request_digest, *, kind, payload,
                state, plan_ref=None, plan_digest=None, authority_refs=(),
                coverage=(), missing_inputs=()):
        material = dict(schema=SCHEMA, kind=kind, namespace=owner.namespace,
                        operation_id=operation_id, request_digest=request_digest,
                        plan_ref=plan_ref, plan_digest=plan_digest,
                        activation_generation=owner.activation_generation,
                        owner_grant_ref=owner.grant_ref,
                        owner_grant_revision=owner.grant_revision,
                        owner_grant_digest=owner.grant_digest,
                        authority_refs=(("owner", owner.authority_ref, owner.authority_digest), *authority_refs),
                        state=state, coverage=tuple(coverage), missing_inputs=tuple(missing_inputs),
                        result=payload, result_digest=digest(payload))
        material["original_ref"] = "d12original:" + canonical_digest(material)
        material["original_digest"] = backend_original_digest_v1(material)
        original = D12BackendOperationOriginalV1(**material)
        encoded = _json(original)
        self.db.execute("INSERT OR IGNORE INTO graph_d12_backend_originals_v1 VALUES(?,?,?,?,?,?)",
                        (*owner.namespace.as_tuple, original.original_ref, operation_id,
                         original.original_digest, encoded))
        if self.original(owner.namespace, original.original_ref) != original:
            raise ValueError("backend original collision")
        changed = self.db.execute("UPDATE graph_d12_backend_operations_v1 SET current_original_ref=? WHERE bot=? AND persona=? AND operation_id=? AND request_digest=?",
                                 (original.original_ref, *owner.namespace.as_tuple, operation_id, request_digest)).rowcount
        if changed != 1:
            raise ValueError("backend original has no original operation")
        return original

    def put_plan(self, namespace, plan_ref, plan_digest, data):
        encoded = _json(data)
        if digest(data) != plan_digest:
            raise ValueError("plan digest differs")
        self.db.execute("INSERT OR IGNORE INTO graph_d12_lifecycle_plans_v1 VALUES(?,?,?,?,?)",
                        (*namespace.as_tuple, plan_ref, plan_digest, encoded))
        if self.plan(namespace, plan_ref) != (plan_digest, json.loads(encoded)):
            raise ValueError("durable plan reference conflict")

    def plan(self, namespace, plan_ref):
        row = self.db.execute("SELECT plan_digest,plan_json FROM graph_d12_lifecycle_plans_v1 WHERE bot=? AND persona=? AND plan_ref=?",
                              (*namespace.as_tuple, plan_ref)).fetchone()
        if row is None:
            raise LookupError("durable lifecycle plan absent")
        value = json.loads(row[1])
        if digest(value) != row[0]:
            raise ValueError("durable lifecycle plan changed")
        return row[0], value

    def step(self, namespace, operation_id, stage):
        return self.db.execute("SELECT intent_digest,receipt_json FROM graph_d12_lifecycle_steps_v1 WHERE bot=? AND persona=? AND operation_id=? AND stage=?",
                               (*namespace.as_tuple, operation_id, stage)).fetchone()

    def begin_step(self, namespace, operation_id, stage, intent):
        identity = digest(intent)
        prior = self.step(namespace, operation_id, stage)
        if prior is not None:
            if prior[0] != identity:
                raise ValueError("maintenance step original identity conflict")
            return prior
        self.db.execute("INSERT INTO graph_d12_lifecycle_steps_v1 VALUES(?,?,?,?,?,NULL)",
                        (*namespace.as_tuple, operation_id, stage, identity))
        return None

    def finish_step(self, namespace, operation_id, stage, receipt):
        encoded = _json(receipt)
        prior = self.step(namespace, operation_id, stage)
        if prior is None:
            raise ValueError("stage receipt without durable intent")
        if prior[1] is not None and prior[1] != encoded:
            raise ValueError("stage receipt changed")
        self.db.execute("UPDATE graph_d12_lifecycle_steps_v1 SET receipt_json=? WHERE bot=? AND persona=? AND operation_id=? AND stage=? AND receipt_json IS NULL",
                        (encoded, *namespace.as_tuple, operation_id, stage))


class LifecycleOperationsV1:
    """Current transfer and control router consumed directly by D12 issuer.

transfer_port resolves current plans/epochs and returns the actual installed
Authority migration service plus its credential. Snapshot/recovery methods
operate under its permits, never under the ordinary source content API. All
method names and positional/keyword contracts below are the installation API.
"""
    def __init__(self, *, store: LifecycleOriginalStoreV1,
                 owner_command_fence: Callable, owner_status_fence: Callable,
                 transfer_port, domain_controls: Mapping[str, object] = (),
                 lifecycle_control_port=None, command_executor=None,
                 status_reader=None):
        self.store = store
        self.owner_command_fence, self.owner_status_fence = owner_command_fence, owner_status_fence
        self.transfer_port = transfer_port
        self.domain_controls = dict(domain_controls)
        self.lifecycle_control_port = lifecycle_control_port
        self.command_executor, self.status_reader = command_executor, status_reader
        self._operations = RLock()

    def _check_owner(self, owner, authority):
        if (type(owner) is not OwnerOperationBindingV1 or
                owner.namespace != authority.namespace or owner.actor != authority.actor or
                owner.activation_generation != authority.activation_generation):
            raise PermissionError("installed current Owner binding differs")

    def read_current_backend_operation_original_v1(self, authority, lease, *, original_ref):
        if self.status_reader is not None:
            return self.status_reader(authority, lease, original_ref=original_ref)
        # Read only the exact content-free original under the dedicated status
        # fence. In particular do not catch denial and retry a content fence.
        with self.store.lock:
            original = self.store.original(authority.namespace, original_ref)
        with self.owner_status_fence(authority, lease, original=original) as owner:
            self._check_owner(owner, authority)
            if (owner.grant_ref, owner.grant_revision, owner.grant_digest,
                    owner.activation_generation) != (original.owner_grant_ref,
                    original.owner_grant_revision, original.owner_grant_digest,
                    original.activation_generation):
                raise PermissionError("current Owner no longer admits this operation")
            with self.store.lock:
                return self.store.original(owner.namespace, original_ref)

    def _command(self, authority, lease, *, operation_id, request_digest,
                 capability, commit, domains=()):
        if self.command_executor is not None:
            return self.command_executor(authority, lease, operation_id=operation_id,
                request_digest=request_digest, capability=capability, commit=commit, domains=domains)
        with self.owner_command_fence(authority, lease, capability=capability) as owner:
            self._check_owner(owner, authority)
            with self.store.transaction():
                return commit(owner)

    def prepare_current_transfer_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        def commit(owner):
            prior = self.store.claim(owner, operation_id, request_digest, "transfer_plan", input_data)
            if prior is not None and prior[4] is not None:
                return self.store.original(owner.namespace, prior[4])
            resolved = self.transfer_port.resolve_current_transfer_plan_v1(owner=owner, input_data=dict(input_data))
            if type(resolved) is not ResolvedTransferPlanV1:
                raise TypeError("installed resolver must return current typed plan")
            payload = resolved.payload
            if (payload.mode != input_data["mode"] or payload.manifest_ref != input_data["manifest_ref"]
                    or payload.snapshot_requirements.namespace != owner.namespace
                    or payload.snapshot_requirements.activation_generation != owner.activation_generation):
                raise StaleRead("transfer resolved request or source generation differs")
            data = asdict(resolved)
            data["owner"] = asdict(owner)
            data["prepare_operation_id"] = operation_id
            plan_digest = digest(data)
            plan_ref = "d12transfer:" + plan_digest[7:]
            self.store.put_plan(owner.namespace, plan_ref, plan_digest, data)
            return self.store.publish(owner, operation_id, request_digest, kind="transfer_plan",
                                      payload=payload, state="completed", plan_ref=plan_ref,
                                      plan_digest=plan_digest,
                                      authority_refs=(("transfer_policy", resolved.policy_ref, resolved.policy_digest),),
                                      coverage=("current_owner", "paired_target", "source_scope_and_rights", "loss_preview"))

        ready = getattr(self.transfer_port, "require_installed_transfer_v1", None)
        if ready is not None:
            ready(input_data)
        resolution = getattr(self.transfer_port, "current_resolution_scope_v1", None)
        with self._operations, (resolution(input_data) if resolution else nullcontext()):
            return self._command(authority, lease, operation_id=operation_id,
                request_digest=request_digest, capability="workbench.transfer", commit=commit)

    def _decode_transfer_plan(self, data):
        item = dict(data["payload"])
        req = dict(item["snapshot_requirements"])
        req["namespace"] = NamespaceId(**req["namespace"])
        item["snapshot_requirements"] = SnapshotRequirementsV2(**req)
        item["loss_coverage"] = tuple(item["loss_coverage"])
        payload = D12TransferPlanPayloadV1(**item)
        raw = data["migration_plan"]
        if raw is not None:
            raw = dict(raw)
            raw["namespace_id"] = NamespaceId(**raw["namespace_id"])
            raw["before_anchor"] = RestoreAnchor(**raw["before_anchor"])
            raw = MigrationPlanV2(**raw)
        return payload, raw

    def execute_current_transfer_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        """Claim under W01; all post-freeze progress belongs to Authority originals."""
        status_port = getattr(self, "operation_status_port", None)
        if status_port is None:
            raise D12PrerequisiteUnavailable("installed_exact_operation_status_port_unavailable")
        with self._operations:
            with self.store.lock:
                existing = self.store.get_operation(authority.namespace, operation_id)
                previous = self.store.original(authority.namespace, existing[4]) if existing and existing[4] else None
            if previous is None:
                def accept(owner):
                    bound = self.store.db.execute("SELECT operation_id FROM graph_d12_backend_operations_v1 WHERE bot=? AND persona=? AND kind='transfer_execution' AND json_extract(input_json,'$.plan_ref')=? AND operation_id!=? LIMIT 1",
                        (*owner.namespace.as_tuple, input_data["plan_ref"], operation_id)).fetchone()
                    if bound is not None:
                        raise StaleRead("transfer plan already has its original execute operation")
                    self.store.claim(owner, operation_id, request_digest, "transfer_execution", input_data)
                    plan_digest, data = self.store.plan(owner.namespace, input_data["plan_ref"])
                    expected = input_data["current_epochs"]
                    if plan_digest != expected["plan_digest"] or data["owner"] != asdict(owner):
                        raise StaleRead("original transfer plan or Owner differs")
                    payload, plan = self._decode_transfer_plan(data)
                    if payload.mode != "relocate":
                        return self.transfer_port.execute_current_artifact_transfer_v1(
                            store=self.store, owner=owner, operation_id=operation_id,
                            request_digest=request_digest, plan_ref=input_data["plan_ref"],
                            plan_digest=plan_digest, plan=data, input_data=dict(input_data))
                    expected_values = {k: data[k] for k in ("graph_revision", "access_epoch", "delete_epoch")}
                    expected_values["activation_generation"] = owner.activation_generation
                    if any(expected[k] != v for k, v in expected_values.items()):
                        raise StaleRead("transfer expected epochs differ from durable plan")
                    target_digest = self.transfer_port.validate_current_transfer_execution_v1(owner=owner,
                        plan=data, expected_epochs=expected, target_lease_ref=input_data["target_lease_ref"])
                    if type(target_digest) is not str or _SHA.fullmatch(target_digest) is None:
                        raise ValueError("current paired target lease digest required")
                    return self.store.publish(owner, operation_id, request_digest,
                        kind="transfer_execution", payload=D12TransferExecutionPayloadV1(
                            plan.transfer_id, "accepted", plan.namespace, digest(plan.before_anchor),
                            target_digest, False, False), state="accepted",
                        plan_ref=input_data["plan_ref"], plan_digest=plan_digest,
                        coverage=("durable_original_operation",))
                resolution = getattr(self.transfer_port, "current_resolution_scope_v1", None)
                with resolution(input_data) if resolution else nullcontext():
                    previous = self._command(authority, lease, operation_id=operation_id,
                        request_digest=request_digest, capability="workbench.transfer", commit=accept)
            elif (existing[0] != request_digest or existing[3] != _json(input_data)
                    or previous.kind != "transfer_execution"):
                raise StaleRead("original transfer execution request differs")
            # Registration is independently durable before freeze. Exact resume
            # authenticates the recorded Owner without an ordinary content fence.
            registered = status_port.ensure_registered_operation_v1(authority, lease, original=previous)
            observed_original = status_port.refresh_current_transfer_status_v1(
                authority, lease, original_ref=registered.original_ref)
            if observed_original.state == "completed":
                return observed_original
            with self.store.lock:
                plan_digest, data = self.store.plan(authority.namespace, previous.plan_ref)
            payload, plan = self._decode_transfer_plan(data)
            service, _ = self.transfer_port.resolve_installed_migration_service_v1(plan=plan,
                owner=OwnerOperationBindingV1(**{**data["owner"], "namespace": authority.namespace}))
            try:
                source_credential, source_subject = self.transfer_port.migration_identity_v1("source")
                target_credential, target_subject = self.transfer_port.migration_identity_v1("target")
                # Each call is idempotent under the original transfer and request IDs.
                # begin replay is also the recovery entry after an unknown response.
                _, status = service.begin_transfer(credential=source_credential, subject=source_subject,
                    plan=plan, request_id=operation_id + ":begin")
                if status.phase == "begun":
                    snapshot = self.transfer_port.read_current_source_snapshot_v2(plan=plan, permit=status.source_permit)
                    if type(snapshot) is not SourceSnapshotReceiptV2:
                        raise TypeError("installed source snapshot receipt required")
                    _, status = service.revoke_source(credential=source_credential, subject=source_subject,
                        permit=status.source_permit, snapshot=snapshot, request_id=operation_id + ":revoke")
                if status.phase == "revoked":
                    _, status = service.prepare_target(credential=target_credential, subject=target_subject,
                        transfer_id=plan.transfer_id, request_id=operation_id + ":target")
                if status.phase == "target_prepared":
                    recovery = self.transfer_port.recover_current_target_graph_v2(plan=plan,
                        permit=status.target_permit, source_snapshot=status.source_snapshot,
                        target_lease_ref=input_data["target_lease_ref"])
                    if type(recovery) is not TargetRecoveryReceiptV2:
                        raise TypeError("installed target recovery original required")
                    _, status = service.activate_target(credential=target_credential, subject=target_subject,
                        permit=status.target_permit, recovery=recovery, request_id=operation_id + ":activate")
                observed = service.recover_transfer(credential=target_credential, subject=target_subject,
                    transfer_id=plan.transfer_id)
                if (observed.history.phase != "activated" or observed.current.anchor != status.current_anchor
                        or observed.current.phase != "active" or observed.current.holder != plan.target_holder):
                    raise StaleRead("target activation is not independently current")
                target_digest = self.transfer_port.read_current_target_lease_digest_v1(
                    plan=plan, target_lease_ref=input_data["target_lease_ref"], current=observed.current)
                if target_digest != previous.result.target_lease_digest:
                    raise StaleRead("original paired target lease changed")
                return status_port.refresh_current_transfer_status_v1(
                    authority, lease, original_ref=registered.original_ref)
            except PermissionError:
                raise
            except Exception as exc:
                # A lost activation ACK is resolved from the same independent
                # Authority original. No second transfer or rollback is issued.
                latest = status_port.refresh_current_transfer_status_v1(
                    authority, lease, original_ref=registered.original_ref)
                if latest.state == "completed":
                    return latest
                raise D12OperationPending(latest) from exc

    def commit_current_control_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        command = ControlCommandV1.from_wire(input_data)
        outside = getattr(self.lifecycle_control_port, "execute_current_lifecycle_control_v1", None)
        if command.control in {"pause", "resume"} and callable(outside):
            with self._operations:
                return outside(authority, lease, operation_id=operation_id, request_digest=request_digest,
                    command=command, input_data=input_data)
        if command.control == "cancel_job":
            if command.config_diff or command.test_intent is not None or not command.object_ref.startswith("job:"):
                raise ValueError("job cancellation accepts only its exact job selector")
        elif command.control in {"pause", "resume", "disable", "retire", "uninstall"}:
            if self.lifecycle_control_port is None:
                raise D12PrerequisiteUnavailable("installed_lifecycle_control_port_unavailable")
        elif command.object_ref.split(":", 1)[0] not in self.domain_controls:
            raise D12PrerequisiteUnavailable("installed_typed_domain_control_unavailable")
        def commit(owner):
            db = self.store.db
            prior = self.store.claim(owner, operation_id, request_digest, "control", input_data)
            if prior is not None and prior[4] is not None:
                return self.store.original(owner.namespace, prior[4])
            if command.control == "cancel_job":
                if command.config_diff or command.test_intent is not None or not command.object_ref.startswith("job:"):
                    raise ValueError("job cancellation accepts only its exact job selector")
                job_id = command.object_ref[4:]
                current = get_job(db, job_id)
                if (current.bot_id, current.persona_id) != owner.namespace.as_tuple:
                    raise PermissionError("job crosses Owner namespace")
                updated = cancel_job(db, job_id, operation_id, request_digest[7:])
                receipt = ControlCommitV1(D12ControlPayloadV1(command.object_ref, command.control,
                    updated.fence, ("joboperation:" + operation_id,), updated.phase == "cancelled"),
                    "completed" if updated.phase == "cancelled" else "cancel_requested",
                    (("persistent_job", "job:" + job_id, digest(updated)),),
                    ("durable_cancel_epoch", "worker_result_fence", "unknown_effects_preserved"))
            else:
                if command.control in {"pause", "resume", "disable", "retire", "uninstall"}:
                    port = self.lifecycle_control_port
                else:
                    # Domain selectors explicitly bind ownership, e.g. d07:...
                    domain = command.object_ref.split(":", 1)[0]
                    port = self.domain_controls.get(domain)
                if port is None:
                    raise LookupError("installed typed control handler unavailable")
                receipt = port.commit_current_control_in_tx_v1(db=db, owner=owner,
                    operation_id=operation_id, request_digest=request_digest, command=command)
                if type(receipt) is not ControlCommitV1:
                    raise TypeError("installed domain control commit receipt required")
            if (receipt.payload.object_ref != command.object_ref or receipt.payload.control != command.control
                    or not receipt.authority_refs):
                raise ValueError("domain control original request binding differs")
            return self.store.publish(owner, operation_id, request_digest, kind="control",
                payload=receipt.payload, state=receipt.state, authority_refs=receipt.authority_refs,
                coverage=receipt.coverage, missing_inputs=receipt.missing_inputs)
        with self._operations:
            return self._command(authority, lease, operation_id=operation_id,
                request_digest=request_digest, capability="workbench.control", commit=commit,
                domains=("d11",) if command.control == "cancel_job" else (
                    (command.object_ref.split(":", 1)[0],) if command.object_ref.split(":", 1)[0]
                    in {"d01", "d02", "d03", "d04", "d05", "d06", "d07", "d08", "d09", "d10", "d11", "d12", "d13"} else ()))


__all__ = ("LifecycleOperationsV1", "LifecycleOriginalStoreV1", "OwnerOperationBindingV1",
           "ResolvedTransferPlanV1", "ControlCommandV1", "ControlCommitV1", "TABLES", "digest")
