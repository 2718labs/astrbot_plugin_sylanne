"""Installed package maintenance with durable intents and observed stage facts.

The release registry and stage executor are installed administrator services.
The browser submits three opaque references, never archive paths or commands.
Package bytes are checked here before a native library or candidate is loaded.
The executor owns process drain, graph/Authority-aware backup, shadow migration,
candidate readiness and activation. Its recovery method queries the *original*
stage; unresolved side effects are never rerun under another operation identity.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import stat
from threading import RLock
from typing import Mapping

from ..contracts import StaleRead
from ..domains.d12.backend_operation_contracts_v1 import D12MaintenancePayloadV1
from ..runtime.lifecycle_operations_v1 import (
    LifecycleOriginalStoreV1, OwnerOperationBindingV1, digest,
)
from .installed_package import verify_installed_backend_runtime_v1

STAGES = ("stage_package", "quiesce", "backup", "migrate_shadow", "candidate_ready", "activate")


@dataclass(frozen=True, slots=True)
class MaintenancePlanV1:
    release_manifest_ref: str
    release_manifest_digest: str
    migration_plan_ref: str
    migration_plan_digest: str
    target_capability: str
    source_package_root: str
    current_installation_digest: str
    previous_installation_ref: str | None
    previous_installation_digest: str | None
    policy_ref: str
    policy_digest: str
    package_version: str
    maximum_bytes: int
    maximum_files: int
    available_cpu_features: tuple[str, ...] = ()
    schema: str = "d12.installed_maintenance_plan.v1"

    def __post_init__(self):
        if self.schema != "d12.installed_maintenance_plan.v1":
            raise ValueError("maintenance plan version differs")
        for name in ("release_manifest_ref", "migration_plan_ref", "target_capability", "policy_ref", "package_version"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("maintenance identities required")
        for name in ("release_manifest_digest", "migration_plan_digest", "current_installation_digest", "policy_digest"):
            _require_digest(getattr(self, name))
        if (self.previous_installation_ref is None) != (self.previous_installation_digest is None):
            raise ValueError("qualified rollback identity must be complete")
        if self.previous_installation_digest is not None:
            _require_digest(self.previous_installation_digest)
        if (not Path(self.source_package_root).is_absolute() or
                any(type(v) is not int or v < 1 for v in (self.maximum_bytes, self.maximum_files))
                or self.maximum_bytes > 8 * 1024**3 or self.maximum_files > 100_000):
            raise ValueError("installed bounded package location required")
        if self.package_version.startswith(("1.", "2.")):
            raise ValueError("retired legacy core cannot be installed or restored")


def _require_digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(char not in "0123456789abcdef" for char in value[7:])):
        raise ValueError("exact SHA-256 digest required")


@dataclass(frozen=True, slots=True)
class MaintenanceStageReceiptV1:
    operation_id: str
    stage: str
    intent_digest: str
    state: str
    receipt_ref: str
    active_installation_digest: str
    facts: Mapping[str, object]
    missing_inputs: tuple[str, ...] = ()

    def __post_init__(self):
        if self.stage not in (*STAGES, "rollback") or self.state not in {
                "completed", "partial", "rejected", "pending_confirmation"}:
            raise ValueError("maintenance stage/state differs")
        if not self.operation_id or not self.receipt_ref:
            raise ValueError("maintenance original identity required")
        _require_digest(self.intent_digest)
        _require_digest(self.active_installation_digest)
        if self.state == "completed" and self.missing_inputs:
            raise ValueError("completed stage cannot be missing inputs")
        if type(self.facts) is not dict or len(json.dumps(self.facts, allow_nan=False)) > 65536:
            raise ValueError("bounded maintenance facts required")


def _no_links(path: Path):
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("package/staging path contains a reparse point")


class InstalledMaintenancePort:
    """D12's maintain port; injectable without opening any running user DB.

registry.resolve_current_maintenance_plan_v1(owner,input_data) ->
MaintenancePlanV1 and registry.verify_release_trust_v1(plan) -> exact True
from the external publisher/admin root, followed by
registry.validate_current_maintenance_plan_v1(owner,plan).

executor.execute_stage_v1/recover_stage_v1(*,operation_id,stage,intent_digest,
plan,staged_root,previous_receipts) -> MaintenanceStageReceiptV1 (recover may
return None for unresolved). executor.read_current_installation_digest_v1
(owner,plan) rereads the installed service identity. No shell is invoked here.
"""
    def __init__(self, *, store: LifecycleOriginalStoreV1, registry,
                 executor, staging_root: Path, owner_command_fence,
                 owner_status_fence):
        if type(store) is not LifecycleOriginalStoreV1:
            raise TypeError("shared lifecycle original store required")
        root = Path(staging_root)
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("administrator-created staging root required")
        _no_links(root)
        self.store, self.registry, self.executor = store, registry, executor
        self.staging_root = root.resolve(strict=True)
        self.owner_command_fence, self.owner_status_fence = owner_command_fence, owner_status_fence
        self._operations = RLock()

    @staticmethod
    def _owner(owner, authority):
        if (type(owner) is not OwnerOperationBindingV1 or
                (owner.namespace, owner.actor, owner.activation_generation) !=
                (authority.namespace, authority.actor, authority.activation_generation)):
            raise PermissionError("current maintenance Owner differs")

    def read_current_backend_operation_original_v1(self, authority, lease, *, original_ref):
        with self.store.lock:
            original = self.store.original(authority.namespace, original_ref)
        with self.owner_status_fence(authority, lease, original=original) as owner:
            self._owner(owner, authority)
            if (owner.grant_ref, owner.grant_revision, owner.grant_digest) != (
                    original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest):
                raise PermissionError("maintenance Owner was revoked or changed")
            with self.store.lock:
                return self.store.original(owner.namespace, original_ref)

    def _publish(self, owner, operation_id, request_digest, plan, plan_ref,
                 plan_digest, stage, state, receipts, missing=()):
        active = self.executor.read_current_installation_digest_v1(owner=owner, plan=plan)
        _require_digest(active)
        payload = D12MaintenancePayloadV1(plan.release_manifest_ref,
            plan.release_manifest_digest, plan.migration_plan_ref,
            plan.target_capability, stage, active,
            tuple(receipt.receipt_ref for receipt in receipts))
        return self.store.publish(owner, operation_id, request_digest,
            kind="maintenance", payload=payload, state=state,
            plan_ref=plan_ref, plan_digest=plan_digest,
            authority_refs=(("release", plan.release_manifest_ref, plan.release_manifest_digest),
                            ("migration_plan", plan.migration_plan_ref, plan.migration_plan_digest),
                            ("maintenance_policy", plan.policy_ref, plan.policy_digest),
                            *(("maintenance_stage", receipt.receipt_ref, digest(receipt)) for receipt in receipts)),
            coverage=("signed_release_trust", "installed_identity", "original_operation_stages"),
            missing_inputs=missing)

    def prepare_install_or_upgrade_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        if set(input_data) != {"release_manifest_ref", "migration_plan_ref", "target_capability"}:
            raise ValueError("maintenance consumes exactly its opaque intent references")
        with self._operations, self.owner_command_fence(authority, lease, capability="workbench.maintain") as owner:
            self._owner(owner, authority)
            with self.store.transaction():
                prior = self.store.claim(owner, operation_id, request_digest, "maintenance", input_data)
                if prior is not None and prior[4] is not None:
                    return self.store.original(owner.namespace, prior[4])
                plan = self.registry.resolve_current_maintenance_plan_v1(owner=owner, input_data=dict(input_data))
                if type(plan) is not MaintenancePlanV1:
                    raise TypeError("installed release/migration plan required")
                if any(getattr(plan, name) != input_data[name] for name in input_data):
                    raise ValueError("installed maintenance plan intent differs")
                if self.registry.verify_release_trust_v1(plan=plan) is not True:
                    raise PermissionError("publisher/administrator release trust failed")
                self.registry.validate_current_maintenance_plan_v1(owner=owner, plan=plan)
                # Validate original bytes before any native code/process change.
                self._verify_package(Path(plan.source_package_root), plan)
                data = {"plan": asdict(plan), "owner": asdict(owner)}
                plan_digest = digest(data)
                plan_ref = "d12maintenance:" + plan_digest[7:]
                self.store.put_plan(owner.namespace, plan_ref, plan_digest, data)
                return self._publish(owner, operation_id, request_digest, plan, plan_ref,
                                     plan_digest, "prepared", "accepted", ())

    def _verify_package(self, root, plan):
        _no_links(root)
        verification = verify_installed_backend_runtime_v1(root, plan.release_manifest_digest[7:],
            available_cpu_features=frozenset(plan.available_cpu_features))
        if (not verification.verified or verification.runtime_scope not in {
                "backend-production-acceptance", "backend-local-alpha2-acceptance", "backend-beta1-server-test", "formal-alpha1"}
                or verification.package_version != plan.package_version):
            raise ValueError("installed backend package qualification failed: " + verification.reason)
        manifest = json.loads((root / "release-manifest.json").read_bytes())
        paths = {entry["path"] for entry in manifest["files"]} | {"release-manifest.json"}
        actual_paths, actual_bytes = set(), 0
        for folder, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                _no_links(Path(folder) / name)
            for name in files:
                path = Path(folder) / name
                _no_links(path)
                if not path.is_file():
                    raise ValueError("package contains a nonregular file")
                actual_paths.add(path.relative_to(root).as_posix())
                actual_bytes += path.stat().st_size
                if len(actual_paths) > plan.maximum_files or actual_bytes > plan.maximum_bytes:
                    raise ValueError("package exceeds installed file/byte budgets")
        if actual_paths != paths:
            raise ValueError("package contains unlisted or absent files")
        return manifest

    def _stage_package(self, operation_id, plan, intent_digest):
        root = self.staging_root / operation_id
        source = Path(plan.source_package_root)
        manifest = self._verify_package(source, plan)
        if root.exists():
            _no_links(root)
        else:
            # Exact manifest paths only; validate separators, case aliases, and
            # junction parents before copy. Interrupted copies stay isolated.
            root.mkdir(mode=0o700)
        entries = [*manifest["files"], {"path": "release-manifest.json",
                "bytes": (source / "release-manifest.json").stat().st_size,
                "sha256": plan.release_manifest_digest[7:]}]
        seen = set()
        for entry in entries:
                relative = PurePosixPath(entry["path"])
                if (relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts)
                        or "\\" in entry["path"] or ":" in entry["path"]
                        or entry["path"].casefold() in seen):
                    raise ValueError("unsafe or aliased release file")
                seen.add(entry["path"].casefold())
                src, dst = source.joinpath(*relative.parts), root.joinpath(*relative.parts)
                _no_links(src)
                dst.parent.mkdir(parents=True, exist_ok=True)
                _no_links(dst.parent)
                if dst.exists():
                    _no_links(dst)
                    if (dst.stat().st_size == entry["bytes"] and sha256(dst.read_bytes()).hexdigest() == entry["sha256"]):
                        continue
                    raise ValueError("existing staged original file differs")
                temporary = dst.with_name(dst.name + ".sylanne-stage-part")
                if temporary.exists():
                    _no_links(temporary)
                actual = sha256()
                count = 0
                with src.open("rb") as incoming, temporary.open("wb") as outgoing:
                    while block := incoming.read(1024 * 1024):
                        count += len(block)
                        if count > entry["bytes"]:
                            raise ValueError("release source grew during stage copy")
                        actual.update(block)
                        outgoing.write(block)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                if count != entry["bytes"] or actual.hexdigest() != entry["sha256"]:
                    raise ValueError("release source changed during stage copy")
                os.replace(temporary, dst)
        self._verify_package(root, plan)
        return MaintenanceStageReceiptV1(operation_id, "stage_package", intent_digest,
            "completed", "maintstage:" + digest((operation_id, "stage_package", plan.release_manifest_digest))[7:],
            plan.current_installation_digest,
            {"release_manifest_digest": plan.release_manifest_digest, "staged_root": str(root),
             "native_abi": 2, "build_mode": manifest["build_mode"],
             "formal_package": manifest["build_mode"] == "formal-alpha1"})

    def _decode_receipt(self, value):
        data = json.loads(value)
        data["missing_inputs"] = tuple(data["missing_inputs"])
        return MaintenanceStageReceiptV1(**data)

    def _validate_stage_facts(self, receipt, plan, previous):
        if receipt.state != "completed":
            return
        required = {
            "quiesce": ("drain_original_ref", "dispatch_admission_closed", "running_jobs_remaining", "retained_unknown_refs"),
            "backup": ("backup_artifact_ref", "graph_snapshot_digest", "deletion_anchor_digest", "execution_anchor_digest", "restore_gate_receipt_ref"),
            "migrate_shadow": ("shadow_graph_ref", "mapping_digest", "schema_version", "source_watermark_digest"),
            "candidate_ready": ("native_load_receipt_ref", "native_load_receipt_digest", "native_abi", "ready_domains", "candidate_installation_digest"),
            "activate": ("activation_original_ref", "activation_generation", "single_active_installation"),
            "rollback": ("recovery_gate_receipt_ref", "qualified_previous_release_digest", "independent_heads_rolled_back", "previous_package_version"),
        }.get(receipt.stage, ())
        facts = receipt.facts
        if any(key not in facts for key in required):
            raise ValueError("completed installed maintenance stage lacks actual facts")
        for key in required:
            if key.endswith("_ref") and (type(facts[key]) is not str or not facts[key]):
                raise ValueError("maintenance stage lacks a durable actual receipt reference")
            if key.endswith("_digest"):
                _require_digest(facts[key])
        if receipt.stage == "quiesce" and (
                facts["dispatch_admission_closed"] is not True or
                type(facts["running_jobs_remaining"]) is not int or facts["running_jobs_remaining"] != 0
                or type(facts["retained_unknown_refs"]) is not list):
            raise ValueError("quiesce must observe drained workers and retained unknowns")
        if receipt.stage == "candidate_ready" and (
                facts["native_abi"] != 2 or type(facts["native_abi"]) is not int
                or facts["ready_domains"] != [f"d{i:02}" for i in range(1, 14)]):
            raise ValueError("candidate readiness must cover actual ABI2 and thirteen domains")
        if receipt.stage == "activate":
            ready = next(item for item in previous if item.stage == "candidate_ready")
            if (facts["single_active_installation"] is not True or
                    type(facts["activation_generation"]) is not int or facts["activation_generation"] < 1
                    or receipt.active_installation_digest != ready.facts["candidate_installation_digest"]):
                raise ValueError("activation differs from the single ready candidate")
        if receipt.stage == "rollback" and (
                facts["qualified_previous_release_digest"] != plan.previous_installation_digest
                or receipt.active_installation_digest != plan.previous_installation_digest
                or facts["independent_heads_rolled_back"] is not False
                or type(facts["previous_package_version"]) is not str
                or facts["previous_package_version"].startswith(("1.", "2."))):
            raise ValueError("rollback lacks a qualified previous release/current independent heads")

    def _step(self, owner, operation_id, stage, plan, plan_digest, receipts):
        intent = {"operation_id": operation_id, "stage": stage, "plan_digest": plan_digest,
                  "previous_receipt_digests": [digest(receipt) for receipt in receipts]}
        identity = digest(intent)
        with self.store.transaction():
            prior = self.store.begin_step(owner.namespace, operation_id, stage, intent)
        kwargs = dict(operation_id=operation_id, stage=stage, intent_digest=identity,
                      plan=plan, staged_root=self.staging_root / operation_id,
                      previous_receipts=tuple(receipts))
        if prior is not None and prior[1] is not None:
            receipt = self._decode_receipt(prior[1])
            self._validate_stage_facts(receipt, plan, receipts)
            return receipt
        if stage == "stage_package":
            # Staging only writes an isolated directory. On restart an existing
            # complete stage is verified; incomplete bytes never run.
            receipt = self._stage_package(operation_id, plan, identity)
        elif prior is not None:
            receipt = self.executor.recover_stage_v1(**kwargs)
            if receipt is None:
                return None
        else:
            receipt = self.executor.execute_stage_v1(**kwargs)
        if (type(receipt) is not MaintenanceStageReceiptV1 or
                (receipt.operation_id, receipt.stage, receipt.intent_digest) !=
                (operation_id, stage, identity)):
            raise ValueError("installed maintenance stage original differs")
        self._validate_stage_facts(receipt, plan, receipts)
        # Facts are meaningful only when the installed executor rereads its
        # durable stage, including drain leases/unknown, both backup anchors,
        # migration mapping, actual native load and current single installation.
        if stage != "stage_package":
            observed = self.executor.recover_stage_v1(**kwargs)
            if observed != receipt:
                raise ValueError("maintenance stage not durably rereadable")
        with self.store.transaction():
            self.store.finish_step(owner.namespace, operation_id, stage, receipt)
        return receipt

    def execute_install_or_upgrade_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        with self._operations:
            with self.store.lock:
                row = self.store.get_operation(authority.namespace, operation_id)
                if row is None or row[4] is None:
                    raise LookupError("prepare durable maintenance plan first")
                original = self.store.original(authority.namespace, row[4])
                plan_digest, data = self.store.plan(authority.namespace, original.plan_ref)
            with self.owner_status_fence(authority, lease, original=original) as owner:
                self._owner(owner, authority)
                plan_data = dict(data["plan"])
                plan_data["available_cpu_features"] = tuple(plan_data["available_cpu_features"])
                plan = MaintenancePlanV1(**plan_data)
                with self.store.transaction():
                    self.store.claim(owner, operation_id, request_digest, "maintenance", input_data)
                    if data["owner"] != asdict(owner) or original.plan_digest != plan_digest:
                        raise StaleRead("maintenance plan or initiating Owner changed")
                    if original.state == "completed":
                        return original
                if self.registry.verify_release_trust_v1(plan=plan) is not True:
                    raise PermissionError("maintenance release trust changed")
            receipts = []
            state, terminal_stage, missing = "completed", "activate", ()
            for stage in STAGES:
                # Maintenance changes generation and stops ordinary content,
                # therefore every stage uses only the bound operation fence.
                with self.owner_status_fence(authority, lease, original=original) as current:
                    if current != owner:
                        raise PermissionError("maintenance initiating Owner changed")
                    receipt = self._step(owner, operation_id, stage, plan, plan_digest, receipts)
                if receipt is None:
                    state, terminal_stage, missing = "pending_confirmation", stage, ("original_stage_outcome_unresolved",)
                    break
                receipts.append(receipt)
                if receipt.state != "completed":
                    state, terminal_stage, missing = receipt.state, stage, receipt.missing_inputs
                    # Only an observed known failure permits rollback. Unknown
                    # activation cannot trigger a blind rollback or second run.
                    if receipt.state == "rejected" and stage != "stage_package" and plan.previous_installation_ref:
                        with self.owner_status_fence(authority, lease, original=original) as current:
                            if current != owner:
                                raise PermissionError("rollback Owner changed")
                            rollback = self._step(owner, operation_id, "rollback", plan, plan_digest, receipts)
                        if rollback is not None:
                            receipts.append(rollback)
                            terminal_stage = "rolled_back" if rollback.state == "completed" else "rollback"
                            state = "partial" if rollback.state == "completed" else rollback.state
                            missing = rollback.missing_inputs
                        else:
                            state, terminal_stage, missing = "pending_confirmation", "rollback", ("original_rollback_outcome_unresolved",)
                    break
            with self.owner_status_fence(authority, lease, original=original) as current:
                if current != owner:
                    raise PermissionError("maintenance completion Owner changed")
                with self.store.transaction():
                    return self._publish(owner, operation_id, request_digest, plan,
                        original.plan_ref, plan_digest, terminal_stage, state, receipts, missing)

    def install_or_upgrade_v1(self, authority, lease, *, operation_id, request_digest, input_data):
        with self.store.lock:
            exists = self.store.get_operation(authority.namespace, operation_id)
        if exists is None:
            self.prepare_install_or_upgrade_v1(authority, lease, operation_id=operation_id,
                                               request_digest=request_digest, input_data=input_data)
        return self.execute_install_or_upgrade_v1(authority, lease, operation_id=operation_id,
                                                  request_digest=request_digest, input_data=input_data)

    def read_maintenance_status_v1(self, authority, lease, *, operation_id):
        with self.store.lock:
            row = self.store.get_operation(authority.namespace, operation_id)
            if row is None or row[4] is None:
                raise LookupError("maintenance operation absent")
        return self.read_current_backend_operation_original_v1(authority, lease, original_ref=row[4])


__all__ = ("InstalledMaintenancePort", "MaintenancePlanV1", "MaintenanceStageReceiptV1", "STAGES")
