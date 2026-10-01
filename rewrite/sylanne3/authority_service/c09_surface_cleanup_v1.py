"""Real managed-file cleanup and independent cold reads for C09's surfaces."""
from __future__ import annotations

from pathlib import Path
from contextlib import closing
import os
import sqlite3

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1, SURFACES, file_observation_v1, _regular_path, _directory_path
from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
from .c09_process_identity_v1 import require_process_retired_v1
from .c09_build_originals_v1 import decode_installed_build_original_v1
from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, _cold_graph_data_root
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2

_GRAPH = frozenset({"graph_current_history", "graph_dependency_history", "source_derived_caches",
    "retrieval_indexes", "jobs_drafts", "experiments_diagnostics", "imports_exports"})
_PHYSICAL = frozenset({"sqlite_wal_free_pages", "execution_journal_payloads"})


def _directory_files(root, *, protected):
    root = _directory_path(root)
    result = []
    def unreadable(exc):
        raise AuthorityUnavailable("C09 managed directory could not be completely enumerated") from exc
    for walk_root, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        dirs.sort(); files.sort()
        for name in dirs:
            resolved = _directory_path(Path(walk_root) / name)
            if not resolved.is_relative_to(root):
                raise AuthorityUnavailable("C09 managed directory escaped registered root")
        for name in files:
            path = Path(walk_root) / name
            resolved = _regular_path(path)
            if not resolved.is_relative_to(root):
                raise AuthorityUnavailable("C09 managed entry escaped registered root")
            if str(resolved) not in protected:
                result.append(file_observation_v1(resolved, exclusive=True))
    return tuple(sorted(result, key=lambda item: item["resolved_path"]))


class InstalledC09SurfaceCleanupV1:
    def __init__(self, *, control, gate, inventory_manifest, surface, registry=None):
        if (type(control) is not C09StorageControlV1 or type(gate) is not InstalledC09WriterGateV1
                or gate.control is not control or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or surface not in SURFACES or inventory_manifest.authority_id != control.authority_id
                or inventory_manifest.installation_id != control.installation_id):
            raise AuthorityUnavailable("actual installed C09 surface composition required")
        if surface == "model_prompt_caches":
            raise AuthorityUnavailable("C09 model prompt caches require installed provider cleanup and independent reader")
        self.control, self.gate, self.inventory, self.surface = control, gate, inventory_manifest, surface
        self.registry = registry

    def _context(self, operation_id, storage_reader):
        if storage_reader is not self.control:
            raise AuthorityUnavailable("C09 cleaner current reader differs")
        context = self.control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if (context.stage not in {"SWITCHED", "CLEANED"}
                or context.prepared_original["operation_id"] != operation_id
                or context.manifest["inventory_manifest_digest"] != self.inventory.manifest_digest):
            raise AuthorityUnavailable("C09 cleaner current operation/inventory differs")
        self.gate.read_quiescence_original_v1(operation_id=operation_id)
        return context

    def _graph_observation(self, context, operation_id):
        saved = self.control.read_build_original_v1(operation_id=operation_id, kind="graph_candidate")
        if saved is None:
            raise AuthorityUnavailable("C09 installed Graph build original absent")
        candidate = decode_installed_build_original_v1(saved["details"]["candidate"], GraphRebaseCandidateV1)
        member = next(m for m in context.manifest["members"] if m["role"] == "graph")
        if candidate.target_path != member["resolved_path"]:
            raise AuthorityUnavailable("C09 cleaned Graph is not current")
        # Selected current stores are legitimately reopened in WAL mode. The
        # actual revoked writer gate qualifies this independent readonly WAL
        # snapshot; immutable reads remain limited to closed preopen files.
        with closing(sqlite3.connect(Path(member["resolved_path"]).as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
            root, cold = _cold_graph_data_root(Path(member["resolved_path"]), candidate.namespace,
                set(candidate.affected_atom_refs), candidate.new_incarnation, candidate.cumulative_erased_key_digests,
                candidate_connection=db, registry=self.registry)
        context.require_current("maintenance")
        if (root, cold) != (candidate.certificate_draft.new_data_root, candidate.certificate_draft.cold_read_digest):
            raise AuthorityUnavailable("C09 actual sanitized Graph root differs")
        return {"kind": "sanitized_graph", "resolved_path": member["resolved_path"],
            "logical_data_root": root, "cold_read_digest": cold,
            "incarnation": candidate.new_incarnation, "tombstone_root": candidate.certificate_draft.tombstone_root}

    def _roots(self):
        roots = [Path(resource.path) for resource in self.inventory.resources
            if resource.kind in {"cache", "export", "controlled_backup", "rebuild_temp"}
            and self.surface in resource.content_coverage]
        if self.surface == "controlled_backups":
            roots += [Path(resource.path) for resource in self.inventory.resources if resource.kind == "controlled_backup"]
        if self.surface == "imports_exports":
            roots += [Path(resource.path) for resource in self.inventory.resources if resource.kind == "export"]
        if self.surface == "sqlite_wal_free_pages":
            roots += [Path(resource.path) for resource in self.inventory.resources if resource.kind == "rebuild_temp"]
        return tuple(sorted(set(roots)))

    def _protected(self, context):
        return {m["resolved_path"] + suffix for m in context.manifest["members"]
            for suffix in ("", "-wal", "-shm", "-journal")}

    def _before_files(self, context):
        protected = self._protected(context)
        files = [item for root in self._roots() for item in _directory_files(root, protected=protected)]
        if self.surface in _PHYSICAL:
            # Exact final fingerprints cover all retired four-store payloads and companions.
            if self.surface == "sqlite_wal_free_pages":
                files += list(context.prepared_original["source_final_fingerprints"])
            else:
                with self.control._db() as db:
                    retired = db.execute("SELECT resolved_path FROM c09_storage_retired_files_v1 "
                        "WHERE installation_id=? AND resource_id='execution' AND retirement_event_digest=?",
                        (self.control.installation_id,
                            self.control.read_operation_event_v1(context.prepared_original["operation_id"], "SWITCHED")["event_digest"])).fetchall()
                files += [item for item in context.prepared_original["source_final_fingerprints"]
                    if any(item["resolved_path"] in {row[0] + suffix for suffix in ("", "-wal", "-shm", "-journal")} for row in retired)]
        result = {}
        for item in files:
            if item["resolved_path"] in protected:
                raise AuthorityUnavailable("C09 purge plan overlaps current file")
            prior = result.get(item["resolved_path"])
            if prior is not None and prior != item:
                raise AuthorityUnavailable("C09 purge inventories disagree on one file")
            result[item["resolved_path"]] = item
        return tuple(value for _, value in sorted(result.items()))

    def _process_observation(self, operation_id):
        intent = self.control.read_operation_event_v1(operation_id, "INTENT")
        original = intent["details"]["quiescence_original"]
        if "authority_process_original" not in original:
            raise AuthorityUnavailable("C09 original Authority process birth identity absent")
        retired = [require_process_retired_v1(original["authority_process_original"])]
        for worker in original.get("retired_worker_originals", []):
            retired.append(require_process_retired_v1(worker["original_process"]))
        for peer in original.get("retired_peer_originals", []):
            retired.append(require_process_retired_v1(peer["original_process"]))
        switched = self.control.read_operation_event_v1(operation_id, "SWITCHED")
        switch_original = switched["details"].get("quiescence_original")
        if switch_original is None:
            raise AuthorityUnavailable("C09 switching process original unavailable")
        self.control.verify_original_v1(switch_original, "quiescence_digest")
        retired.append(require_process_retired_v1(switch_original["authority_process_original"]))
        return {"kind": "actual_process_retirement", "retired_processes": retired}

    def _execution_observation(self, operation_id):
        from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4
        from ..runtime_contracts import canonical_digest
        resolver = InstalledSanitizedRecoveryResolverV4(storage_reader=self.control)
        context, frames = resolver.read_verified_frames_v4()
        if not frames or frames[-1][0]["operation_id"] != operation_id:
            raise AuthorityUnavailable("C09 current sanitized recovery frame unavailable")
        ids = sorted({fact.execution_id for _, facts, _ in frames for fact in facts.executions})
        reads = []
        for execution_id in ids:
            read = resolver.read_sanitized_execution_v4(
                namespace=context.prepared_original["namespace"], execution_id=execution_id)
            if read is None:
                raise AuthorityUnavailable("C09 historical execution recovery unavailable")
            reads.append((execution_id, canonical_digest(read)))
        return {"kind": "sanitized_execution_recovery", "execution_count": len(reads),
            "typed_recovery_root": canonical_digest(tuple(reads)),
            "frame_digests": [original["prepared_digest"] for original, _, _ in frames]}

    def _after(self, context, operation_id, plan):
        observations = []
        if self.surface in _GRAPH:
            observations.append(self._graph_observation(context, operation_id))
        if self.surface == "process_local_caches":
            observations.append(self._process_observation(operation_id))
        if self.surface == "execution_journal_payloads":
            observations.append(self._execution_observation(operation_id))
        for before in plan["details"]["files"]:
            path = Path(before["resolved_path"])
            if path.exists():
                raise AuthorityUnavailable("C09 managed old bytes remain: " + str(path))
            observations.append({"kind": "removed_file", "resolved_path": str(path), "state": "absent"})
        for root in self._roots():
            remaining = _directory_files(root, protected=self._protected(context))
            if remaining:
                raise AuthorityUnavailable("C09 managed directory still contains unretired bytes")
            observations.append({"kind": "managed_directory", "resolved_path": str(root), "state": "empty_of_retired_files"})
        if not observations:
            raise AuthorityUnavailable("C09 surface lacks registered real observations: " + self.surface)
        return observations

    def clean_installed_surface_v1(self, *, operation_id, storage_reader):
        context = self._context(operation_id, storage_reader)
        # Recovery obligations must be independently readable before the first
        # retired journal byte is removed, including resumptions after crashes.
        if self.surface in _PHYSICAL:
            self._execution_observation(operation_id)
        kind = "purge_" + self.surface
        plan = self.control.read_build_original_v1(operation_id=operation_id, kind=kind)
        if plan is None:
            files = self._before_files(context)
            if self.surface == "controlled_backups" and files:
                raise AuthorityUnavailable("C09 nonempty backups require installed namespace-qualified sanitizing replacement")
            plan = self.control.record_cleanup_plan_v1(operation_id=operation_id, surface=self.surface,
                details={"inventory_manifest_digest": self.inventory.manifest_digest,
                    "files": list(files), "roots": [str(root) for root in self._roots()]})
        if (plan["manifest_digest"] != context.manifest_digest
                or plan["details"]["inventory_manifest_digest"] != self.inventory.manifest_digest):
            raise AuthorityUnavailable("C09 managed purge plan scope differs")
        for before in plan["details"]["files"]:
            path = Path(before["resolved_path"])
            if path.exists():
                if file_observation_v1(path, exclusive=True) != before:
                    raise AuthorityUnavailable("C09 managed file changed before unlink")
                path.unlink()
        after = self._after(context, operation_id, plan)
        return self.control.sign_original_v1("sylanne3.c09.surface-evidence.v1", {
            "schema": "sylanne3.c09.surface-evidence.v1", "installation_id": self.control.installation_id,
            "issuer_id": self.control.authority_id, "operation_id": operation_id, "surface": self.surface,
            "manifest_digest": context.manifest_digest, "action": "sanitized" if self.surface in _GRAPH else "purged",
            "plan_digest": plan["original_digest"], "before_observations": plan["details"]["files"],
            "after_observations": after}, "evidence_digest")

    def reread_installed_surface_v1(self, *, operation_id, storage_reader, original):
        context = self._context(operation_id, storage_reader)
        self.control.verify_original_v1(original, "evidence_digest")
        plan = self.control.read_build_original_v1(operation_id=operation_id, kind="purge_" + self.surface)
        if (plan is None or original["plan_digest"] != plan["original_digest"]
                or original["manifest_digest"] != context.manifest_digest
                or original["surface"] != self.surface or original["operation_id"] != operation_id):
            raise AuthorityUnavailable("C09 independent surface original differs")
        after = self._after(context, operation_id, plan)
        if after != original["after_observations"]:
            raise AuthorityUnavailable("C09 independent actual after-observations differ")
        return {"evidence_digest": original["evidence_digest"], "after_observations": after}
