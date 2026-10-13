"""Actual stopped-cohort compatibility for the bounded no-migration lane.

This lane deliberately requires the complete persistence runtime to have the
same Python AST, semantic resources, dependencies and native bytes. It can admit
packaging, documentation and UI changes; a changed interpretation requires a
separate installed migration contract. Authenticated whole-store roots preserve
originals not yet covered by a dedicated row decoder. Table names alone never
establish compatibility.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import InstalledC09StorageReaderV1, file_observation_v1
from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
from .d12_managed_backup_v2 import InstalledD12ManagedBackupV2, decode_backup_source_v2
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2, _canonical
from .d12_package_history_eligibility_v1 import (
    COMPATIBILITY_SCHEMA, InstalledPackageHistoryEligibilityV1,
    decode_package_compatibility_original_v2,
)
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
from .d12_sqlite_backup_v2 import sqlite_logical_inventory_v2
from ..runtime_contracts import canonical_digest

WORKER_SCHEMA = "d12.candidate-readonly-qualification.v2"


def _stopped_sqlite_observations_v2(path):
    """Bind durable DB/WAL bytes and the identity/shape of SQLite's wal-index.

    A real read-only WAL reader updates SHM read marks. Those transient lock
    bytes are not durable database contents; replacing, resizing, creating or
    removing the SHM file still changes this observation. This helper grants
    no quiescence: its caller must hold the actual lease and verify both units.
    """
    result = []
    for suffix in ("", "-wal", "-shm", "-journal"):
        companion = Path(str(path) + suffix)
        observed = file_observation_v1(companion) if companion.exists() else None
        if suffix == "-shm" and observed is not None:
            if observed["prepared_size"] < 32768 or observed["prepared_size"] % 32768:
                raise AuthorityUnavailable("stopped SQLite SHM shape is invalid")
            observed = {key: observed[key] for key in
                ("resolved_path", "device", "file_id", "prepared_size")}
        result.append(observed)
    return tuple(result)


def _interpretation(root):
    """Fixed complete interpretation closure, never selected by the request."""
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    rows = {}
    for entry in manifest["files"]:
        name = entry["path"]
        if name.endswith(".py"):
            tree = ast.parse((root / name).read_bytes(), filename=name)
            rows[name] = hashlib.sha256(ast.dump(tree, include_attributes=False).encode()).hexdigest()
        elif (name.startswith("rewrite/sylanne3/") or name.startswith("resources/")
                or name in {"requirements.txt", "requirements-authority.txt", "_conf_schema.json", "rewrite/__init__.py"}):
            # No semantic resource is excluded merely because it looks unused.
            rows[name] = entry["sha256"]
    if not rows or "rewrite/sylanne3/runtime_contracts.py" not in rows:
        raise AuthorityUnavailable("complete installed interpretation closure absent")
    return {"files": rows, "platform": manifest["platform"], "native": manifest["native"],
        "native_math": manifest["native_math"]}


def _run_candidate_readonly_worker_v2(package_root, manifest_sha256, copies, namespace, authority_namespace):
    """Detached actual decoder only; its result does not authorize a switch."""
    packet = _canonical(dict(schema=WORKER_SCHEMA, package_root=str(package_root),
        manifest_sha256=manifest_sha256, copies=copies, namespace=namespace,
        authority_namespace=authority_namespace))
    if len(packet) > 65536:
        raise AuthorityUnavailable("candidate qualification request exceeds fixed bound")
    worker = Path(__file__).with_name("d12_candidate_readonly_worker_v2.py")
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(worker)], input=packet,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"LANG": "C.UTF-8"},
            cwd="/", close_fds=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuthorityUnavailable("candidate fixed read-only qualification unavailable") from exc
    if result.returncode or len(result.stdout) > 65536:
        raise AuthorityUnavailable("candidate fixed decoder or native/catalogue qualification failed")
    value = json.loads(result.stdout)
    if (type(value) is not dict or set(value) != {"schema", "request_sha256", "result"}
            or value["schema"] != WORKER_SCHEMA
            or value["request_sha256"] != hashlib.sha256(packet).hexdigest()):
        raise AuthorityUnavailable("candidate qualification response binding differs")
    return value["result"]


class InstalledD12CandidateCompatibilityV2:
    def __init__(self, package_files, supervisor_journal, storage_reader, managed_backup):
        if (type(package_files) is not InstalledPackageSelectionFilesV2
                or type(supervisor_journal) is not InstalledPackageSupervisorJournalV2
                or not isinstance(storage_reader, InstalledC09StorageReaderV1)
                or type(managed_backup) is not InstalledD12ManagedBackupV2
                or managed_backup.files is not package_files or managed_backup.journal is not supervisor_journal
                or managed_backup.reader is not storage_reader
                or package_files.control_directory != supervisor_journal.directory):
            raise TypeError("actual common installed compatibility composition required")
        self.files, self.journal, self.reader, self.backup = package_files, supervisor_journal, storage_reader, managed_backup

    def verify_current_candidate_v2(self, operation_id):
        intent = self.journal.read_verified_intent_v2(operation_id)
        receipts = self.journal.read_verified_receipts_v2(operation_id)
        pending = self.journal.read_verified_pending_stage_v2(operation_id)
        if intent is None or len(intent.namespace_cohort) != 1:
            raise AuthorityUnavailable("exact accepted single-namespace maintenance original required")
        rollback = any(r.stage == "rollback_retire_intent" for r in receipts)
        phase = "rollback" if rollback else "forward"
        stage = "rollback_compatible_current_data" if rollback else "compatible_no_data_migration"
        completed = [r for r in receipts if r.stage == stage]
        if not completed and (pending is None or pending["stage"] != stage
                or not receipts or receipts[-1].stage != ("rollback_backup_ready" if rollback else "backup_ready")):
            raise AuthorityUnavailable("exact durable compatibility stage and completed backup required")
        selection, source_cohort, _ = self.files.read_selected_configuration_cohort_v2()
        if not rollback and (selection.selection_digest != intent.expected_selection_digest
                or selection.revision != intent.expected_selection_revision
                or selection.package_epoch != intent.expected_package_epoch):
            raise AuthorityUnavailable("forward compatibility source selection changed")
        if rollback and (selection.operation_id != operation_id
                or selection.revision != intent.expected_selection_revision + 1
                or selection.package_epoch != intent.expected_package_epoch + 1
                or selection.manifest_sha256 != intent.candidate_manifest_sha256
                or selection.cohort_digest != intent.candidate_cohort_digest):
            raise AuthorityUnavailable("rollback compatibility requires the actual switched candidate")
        target_ref = intent.old_cohort_ref if rollback else intent.candidate_cohort_ref
        installation, candidate = self.files.read_registered_cohort_v2(target_ref)
        expected_digest = intent.old_cohort_digest if rollback else intent.candidate_cohort_digest
        if (installation != intent.installation_id or candidate.cohort_digest != expected_digest
                or candidate.identity_commitment != source_cohort.identity_commitment
                or candidate.credential_profile_directory != source_cohort.credential_profile_directory
                or candidate.compatibility_plan_ref != source_cohort.compatibility_plan_ref
                or candidate.supervisor_policy_digest != intent.supervisor_policy_digest):
            raise AuthorityUnavailable("candidate configuration changes installed identity or policy")
        candidate_configuration = read_verified_configuration_cohort_v2(candidate)
        policy, host_policy, authority_policy = read_fixed_supervisor_policy_v2(self.files)
        if (self.backup.host.config != host_policy or self.backup.authority.config != authority_policy
                or policy["namespace_cohort"] != list(intent.namespace_cohort)
                or policy["authority_id"] != intent.authority_id):
            raise AuthorityUnavailable("candidate verifier differs from fixed independent supervisor")
        if not Path(__file__).resolve().is_relative_to(Path(policy["bootstrap_root"]) / "runtime/rewrite/sylanne3"):
            raise AuthorityUnavailable("candidate qualifier must run from the independent fixed bootstrap runtime")
        _, original_cohort = self.files.read_registered_cohort_v2(intent.old_cohort_ref)
        _, requested_cohort = self.files.read_registered_cohort_v2(intent.candidate_cohort_ref)
        plan = dict(schema="d12.registered-compatible-plan.v2", plan_ref=policy["compatibility_plan_ref"],
            source_cohort_digest=original_cohort.cohort_digest, candidate_cohort_digest=requested_cohort.cohort_digest,
            identity_commitment=requested_cohort.identity_commitment, mode="compatible_package_switch")
        if (canonical_digest(plan) != intent.compatibility_plan_digest
                or original_cohort.cohort_digest != intent.old_cohort_digest
                or requested_cohort.cohort_digest != intent.candidate_cohort_digest):
            raise AuthorityUnavailable("actual registered compatibility plan differs from accepted original")
        self.reader.lease.require_held()
        self.backup._require_composition()
        states = tuple(s.read_current_host_state_v1() for s in (self.backup.host, self.backup.authority))
        if any(not state.stopped_and_drained for state in states):
            raise AuthorityUnavailable("both fixed units must remain actually retired")
        backup = self.backup.read_managed_backup_v2(operation_id, backup_phase=phase)
        observations = {}
        for receipt in receipts:
            for ref, commitment in receipt.observation_refs:
                if ref == intent.accepted_original_ref:
                    continue
                actual = self.journal.read_verified_observation_v2(operation_id, ref)
                if actual.observation_digest != commitment:
                    raise AuthorityUnavailable("compatibility observation receipt differs")
                observations[ref] = actual
        matches = [o for o in observations.values() if o.kind == "managed_backup" and o.body == backup]
        if len(matches) != 1:
            raise AuthorityUnavailable("exact managed backup has no unique signed observation")
        backup_observation = matches[0]
        source_observation = observations.get(backup["source_observation_ref"])
        if (source_observation is None or source_observation.kind != "backup_source"
                or source_observation.observation_digest != backup["source_observation_digest"]):
            raise AuthorityUnavailable("managed backup lacks actual authenticated source")
        source = decode_backup_source_v2(source_observation.body)
        inventories = {role: copy["logical_inventory"] for role, copy in backup["copies"].items()}
        if (source["backup_phase"] != phase or source["selection_digest"] != selection.selection_digest
                or source["accepted_original_digest"] != intent.digest or source["source_digest"] != backup["source_digest"]
                or source["logical_inventories"] != inventories or source["history_inventory"] != backup["history_inventory"]
                or source["storage_identity"] != backup["storage_identity"]):
            raise AuthorityUnavailable("backup does not cover this actual current-data selection")
        context = self.reader.read_verified_current_storage_v1()
        context.require_current("maintenance")
        storage = dict(pointer_version=context.pointer_version, manifest_digest=context.manifest_digest,
            storage_generation=context.storage_generation, members=[{key: m[key] for key in
                ("role", "resolved_path", "device", "file_id", "incarnation_or_journal_id")} for m in context.manifest["members"]])
        if storage != backup["storage_identity"] or context.stage not in {"READY", "RELEASED"}:
            raise AuthorityUnavailable("actual current storage selection differs from backup")
        before_files = []
        deadline = time.monotonic() + 120
        for member in storage["members"]:
            path = Path(member["resolved_path"])
            companions = _stopped_sqlite_observations_v2(path)
            # Closed sidecar-free stores use immutable RO, avoiding SQLite's
            # creation of WAL/SHM during a purported observation. An existing
            # WAL needs its actual existing SHM; never ignore committed WAL.
            if any(companions[1:]) and (companions[1] is None or companions[2] is None or companions[3] is not None):
                raise AuthorityUnavailable("stopped current SQLite companions need qualified recovery before compatibility")
            uri = path.as_uri() + ("?mode=ro&immutable=1" if not any(companions[1:]) else "?mode=ro")
            db = sqlite3.connect(uri, uri=True, isolation_level=None)
            try:
                db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
                if member['role'] == 'core':
                    from .graph_catalogue_upgrade_v1 import (
                        require_no_pending_catalogue_upgrade_in_tx_v1,
                        validate_catalogue_upgrade_core_schema_v1,
                    )
                    validate_catalogue_upgrade_core_schema_v1(db)
                    require_no_pending_catalogue_upgrade_in_tx_v1(db,intent.namespace_cohort[0])
                elif member['role'] == 'graph':
                    from ..runtime.graph_catalogue_upgrade_v1 import current_catalogue_hash_v1
                    if current_catalogue_hash_v1(db) != candidate_configuration['host_profile']['installation_policy']['catalogue_hash']:
                        raise AuthorityUnavailable('package candidate cannot restart another Graph catalogue')
                if (db.execute("PRAGMA quick_check").fetchone() != ("ok",)
                        or sqlite_logical_inventory_v2(db, maximum_rows=100000, deadline=deadline) != inventories[member["role"]]):
                    raise AuthorityUnavailable("current data changed since its authenticated backup")
            finally:
                db.close()
            before_files.append((path, companions))
        history = InstalledPackageHistoryEligibilityV1(package_files=self.files,
            supervisor_journal=self.journal, authority_namespace=intent.namespace_cohort[0]).read_actual_selection_history_v1()
        manifests = {r["manifest_sha256"] for r in backup["history_inventory"]["manifest_groups"]}
        if not manifests.issubset(history.ever_active_manifests):
            raise AuthorityUnavailable("an actual historical original has no ever-active package proof")
        source_root = Path(source_cohort.package.package_root)
        self.files.verify_registered_package_v2(source_cohort.package)
        self.files.verify_registered_package_v2(candidate.package)
        interpretation = _interpretation(source_root)
        if _interpretation(Path(candidate.package.package_root)) != interpretation:
            raise AuthorityUnavailable("changed runtime interpretation requires an explicit migration contract")
        # Retained originals must have the same interpretation, not merely an
        # arbitrary registration or a matching scalar ABI number.
        for manifest in sorted(manifests):
            _, retained = self.files.read_registered_cohort_for_manifest_v2(manifest)
            self.files.verify_registered_package_v2(retained.package)
            if (retained.identity_commitment != candidate.identity_commitment
                    or _interpretation(Path(retained.package.package_root)) != interpretation):
                raise AuthorityUnavailable("historical originals require a different installed interpretation")
        decoded = _run_candidate_readonly_worker_v2(candidate.package.package_root,
            candidate.package.manifest_sha256, backup["copies"], backup["reconciliation"]["namespace"], backup["namespace"])
        for path, before in before_files:
            after = _stopped_sqlite_observations_v2(path)
            if after != before:
                raise AuthorityUnavailable("stopped current store changed during compatibility verification")
        if (self.files.read_selected_package_v2()[0] != selection
                or self.journal.read_verified_receipts_v2(operation_id) != receipts
                or self.journal.read_verified_pending_stage_v2(operation_id) != pending
                or tuple(s.read_current_host_state_v1() for s in (self.backup.host, self.backup.authority)) != states):
            raise AuthorityUnavailable("maintenance stage, selection or retired process changed")
        context.require_current("maintenance"); self.reader.lease.require_held()
        self.backup.read_managed_backup_v2(operation_id, backup_phase=phase)
        body = dict(schema=COMPATIBILITY_SCHEMA, operation_id=operation_id,
            accepted_original_digest=intent.digest, before_selection_digest=selection.selection_digest,
            candidate_cohort_ref=candidate.cohort_ref, candidate_cohort_digest=candidate.cohort_digest,
            candidate_manifest_sha256=candidate.package.manifest_sha256,
            backup_observation_ref=backup_observation.observation_ref,
            backup_observation_digest=backup_observation.observation_digest,
            history_inventory_digest=backup["history_inventory"]["inventory_digest"],
            storage_identity_digest=canonical_digest(storage), logical_inventory_digest=canonical_digest(inventories),
            readers_digest=canonical_digest(("full-runtime-ast-exact-resources-native-v2", interpretation, decoded)),
            compatibility_plan_digest=intent.compatibility_plan_digest, disposition="same_schema_current_data")
        body["compatibility_digest"] = canonical_digest(body)
        value = decode_package_compatibility_original_v2(body)
        if completed:
            originals = [observations[ref].body for ref, _ in completed[-1].observation_refs
                if ref in observations and observations[ref].kind == "package_compatibility"]
            if originals != [value]:
                raise AuthorityUnavailable("compatibility replay differs from its frozen original")
            return originals[0]
        return value
