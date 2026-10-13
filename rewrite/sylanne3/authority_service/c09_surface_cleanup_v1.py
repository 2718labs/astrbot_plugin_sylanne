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

    def advance_installed_surface_v3(self, *, operation_id, storage_reader, view, meter):
        if storage_reader is not self.control or self.surface == 'controlled_backups':
            raise AuthorityUnavailable('actual installed selected surface or specialized backup reader required')
        progress = getattr(self, '_selected_surface_progress_v3', None)
        if progress is None:
            progress = InstalledC09SurfaceProgressV3(self, view, operation_id)
            self._selected_surface_progress_v3 = progress
        elif progress.view is not view or progress.operation_id != operation_id:
            raise AuthorityUnavailable('actual surface progress belongs to another selected operation')
        return progress.advance(meter)

    def advance_installed_surface_reread_v3(self, *, operation_id, storage_reader, view, meter, original):
        if storage_reader is not self.control or self.surface == 'controlled_backups':
            raise AuthorityUnavailable('actual specialized independent surface reader required')
        progress = getattr(self, '_selected_surface_reread_v3', None)
        if progress is None:
            progress = InstalledC09SurfaceProgressV3(self, view, operation_id, saved_original=original)
            self._selected_surface_reread_v3 = progress
        elif progress.view is not view or progress.operation_id != operation_id or progress.saved_original != original:
            raise AuthorityUnavailable('actual surface independent reread selection changed')
        return progress.advance(meter)

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
            from .c09_durable_unlink_v2 import unlink_inventory_member_durably_v2
            self.control.lease.require_held()
            unlink_inventory_member_durably_v2(before)
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


class _FrozenSurfaceInventoryReadV3:
    """Authenticate the actual two-pass Control records before any disposal."""
    def __init__(self, view):
        self.view, self.details, self.page = view, None, None
        self.after = b''
        self.count = self.page_index = self.page_offset = 0
        self.record_root = self.page_root = self.pages_root = '0' * 64
        self.complete = False

    def advance(self, meter):
        from .c09_prepared_storage_v3 import _read_original
        from .c09_selected_history_v3 import _read_one, _bounded
        from .c09_physical_inventory_stream_v2 import _key
        from ..runtime_contracts import canonical_digest
        view = self.view;view.require_current(meter=meter)
        with view.basis.control._db() as db:
            if self.details is None:
                self.details = _read_original(view.basis.control, db, view.basis.prepared['operation_id'],
                    'frozen_inventory_complete_v2', view.basis.manifest['physical_inventory_complete_original_digest'], meter)
                if (self.details['scope_digest'] != view.scope.scope_digest
                        or self.details['record_root'] != view.basis.manifest['physical_inventory_root']
                        or self.details['eof_observation_digest'] != view.basis.manifest['physical_inventory_eof_digest']):
                    raise AuthorityUnavailable('actual selected frozen filesystem original differs')
                return False
            stream = self.details['stream_id']
            if self.page is None and self.page_index < self.details['page_count']:
                self.page = _read_one(db, 'SELECT first_path_key,last_path_key,record_count,page_root FROM c09_physical_inventory_pages_v2 '
                    'WHERE stream_id=? AND pass_index=2 AND page_index=?', (stream, self.page_index), meter)
                if self.page is None or not 1 <= self.page[2] <= 100:
                    raise AuthorityUnavailable('actual frozen filesystem page descriptor absent or malformed')
                self.page_offset = 0;self.page_root = '0' * 64
                return False
            row = _read_one(db, 'SELECT path_key,resource_id,path,commitment FROM c09_physical_inventory_records_v2 '
                'WHERE stream_id=? AND pass_index=2 AND path_key>? ORDER BY path_key LIMIT 1', (stream, self.after), meter)
            if self.page is not None:
                if (row is None or row[0] != _key(row[2], row[1]) or not self.page[0] <= row[0] <= self.page[1]
                        or self.page_offset == 0 and row[0] != self.page[0]):
                    raise AuthorityUnavailable('actual frozen filesystem page omits or changes a record')
                value = (row[0].hex(), row[1], row[3])
                self.record_root = canonical_digest((self.record_root, *value))
                self.page_root = canonical_digest((self.page_root, *value))
                self.after, self.count, self.page_offset = row[0], self.count + 1, self.page_offset + 1
                if self.page_offset == self.page[2]:
                    if self.after != self.page[1] or self.page_root != self.page[3]:
                        raise AuthorityUnavailable('actual frozen filesystem page did not reach its signed boundary')
                    self.pages_root = canonical_digest((self.pages_root, self.page_root))
                    self.page = None;self.page_index += 1
                return False
            if (row is not None or self.count != self.details['record_count'] or self.record_root != self.details['record_root']
                    or self.pages_root != self.details['page_root'] or self.page_index != self.details['page_count']
                    or _read_one(db, 'SELECT 1 FROM c09_physical_inventory_pages_v2 WHERE stream_id=? AND pass_index=2 AND page_index>=? LIMIT 1',
                        (stream, self.page_index), meter) is not None):
                raise AuthorityUnavailable('actual frozen filesystem stream has missing or extra material at EOF')
            status = _bounded(db, meter).execute('SELECT source_domain_digest,phase,result_json FROM c09_physical_inventory_streams_v2 WHERE stream_id=?', (stream,)).fetchone()
            if status is None or status[:2] != (self.details['source_domain_digest'], 'complete'):
                raise AuthorityUnavailable('actual two-pass filesystem completion state differs')
            import json
            result = json.loads(status[2])
            if (result['record_count'], result['record_root'], result['page_root'], result['eof_observation_digest']) != (
                    self.count, self.record_root, self.pages_root, self.details['eof_observation_digest']):
                raise AuthorityUnavailable('actual frozen filesystem census completion differs from its original')
            self.complete = True
            return True


_SURFACE_PLAN_DDL_V3 = 'CREATE TABLE c09_surface_file_plans_v3 (selection_digest TEXT NOT NULL,resolved_path TEXT NOT NULL,plan_json TEXT NOT NULL,plan_digest TEXT NOT NULL UNIQUE,PRIMARY KEY(selection_digest,resolved_path)) STRICT'
_SURFACE_EFFECT_DDL_V3 = 'CREATE TABLE c09_surface_file_effects_v3 (selection_digest TEXT NOT NULL,resolved_path TEXT NOT NULL,effect_json TEXT NOT NULL,effect_digest TEXT NOT NULL UNIQUE,PRIMARY KEY(selection_digest,resolved_path)) STRICT'
_SURFACE_FRONTIER_DDL_V3 = 'CREATE TABLE c09_surface_directory_progress_v3 (selection_digest TEXT NOT NULL,surface TEXT NOT NULL,scan_id TEXT NOT NULL,root_path TEXT NOT NULL,directory_path TEXT NOT NULL,device INTEGER NOT NULL,file_id INTEGER NOT NULL,scanned INTEGER NOT NULL CHECK(scanned IN (0,1)),PRIMARY KEY(selection_digest,surface,scan_id,directory_path)) STRICT'
_SURFACE_EFFECT_PATH_INDEX_V3 = 'CREATE INDEX c09_surface_effect_path_v3 ON c09_surface_file_effects_v3(resolved_path,selection_digest)'
_SURFACE_FRONTIER_INDEX_V3 = 'CREATE INDEX c09_surface_directory_next_v3 ON c09_surface_directory_progress_v3(selection_digest,surface,scan_id,scanned,directory_path)'


def _install_surface_progress_schema_v3(control, db, meter):
    from .c09_selected_history_v3 import _read_one
    for table, ddl in (('c09_surface_file_plans_v3', _SURFACE_PLAN_DDL_V3), ('c09_surface_file_effects_v3', _SURFACE_EFFECT_DDL_V3),
                       ('c09_surface_directory_progress_v3', _SURFACE_FRONTIER_DDL_V3)):
        existing = _read_one(db, "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,), meter)
        if existing is None:
            meter.write(db, ddl)
            if table != 'c09_surface_directory_progress_v3':
                for action in ('UPDATE', 'DELETE'):
                    meter.write(db, control._immutable_ddl(table, action))
        elif existing != (ddl,):
            raise AuthorityUnavailable('actual surface progress schema differs')
        if table != 'c09_surface_directory_progress_v3':
            for action in ('UPDATE', 'DELETE'):
                if _read_one(db, "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (table + '_no_' + action.lower(),), meter) != (control._immutable_ddl(table, action),):
                    raise AuthorityUnavailable('actual surface disposal original is not immutable')

    row = _read_one(db, "SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_surface_effect_path_v3'", (), meter)
    if row is None:meter.write(db, _SURFACE_EFFECT_PATH_INDEX_V3)
    elif row != (_SURFACE_EFFECT_PATH_INDEX_V3,):raise AuthorityUnavailable('actual surface effect path index differs')
    row = _read_one(db, "SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_surface_directory_next_v3'", (), meter)
    if row is None:meter.write(db, _SURFACE_FRONTIER_INDEX_V3)
    elif row != (_SURFACE_FRONTIER_INDEX_V3,):raise AuthorityUnavailable('actual directory frontier index differs')


class InstalledC09SurfaceProgressV3:
    """Frozen record coverage, one locked file, and complete independent directory EOF."""
    def __init__(self, service, view, operation_id, *, saved_original=None):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not service.control:
            raise AuthorityUnavailable('actual complete private selected surface view required')
        self.service, self.view, self.operation_id = service, view, operation_id
        self.inventory = _FrozenSurfaceInventoryReadV3(view)
        self.phase, self.after, self.current_record = 'schema', b'', None
        self.file = self.file_plan = None
        self.file_index = 0;self.file_fragment_root = '0' * 64
        self.removed_count = 0
        from ..runtime_contracts import canonical_digest
        self.removed_root = canonical_digest(('sylanne3.c09.surface-removals.v3', view.basis.selection_digest, service.surface))
        self.root_index = 0;self.directory = self.directory_row = None
        self.directory_count = self.entry_count = 0
        self.directory_root = canonical_digest(('sylanne3.c09.surface-directories.v3', view.basis.selection_digest, service.surface))
        self.failed = self.original = None
        self.saved_original = saved_original
        self.walker = None
        service.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        from sys import getsizeof
        amount=8192
        for value in (self.current_record,self.inventory.page,self.file_plan,self.saved_original,self.original):
            if value is not None:
                amount+=getsizeof(value)+sum(getsizeof(item) for item in (value.values() if type(value) is dict else value))
        return amount

    def close(self):
        if self.file is not None:
            self.file.close();self.file = None
        if self.walker is not None:
            self.walker.close()

    def advance(self, meter):
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            return self._advance(meter)
        except BaseException as exc:
            self.failed = str(exc);self.close()
            raise

    def _selected_record(self, record):
        resource, path = record[1], Path(record[2])
        if str(path) in self.service._protected(self.view.basis.control.read_verified_current_storage_v3(verify_files=False)):
            return False
        if resource.startswith('registered:'):
            actual = next((item for item in self.service.inventory.resources if 'registered:' + item.resource_id == resource), None)
            if actual is None or not path.is_relative_to(Path(actual.path)):
                raise AuthorityUnavailable('actual frozen surface record is outside its registered root')
            return (self.service.surface in actual.content_coverage or self.service.surface == 'imports_exports' and actual.kind == 'export'
                    or self.service.surface == 'sqlite_wal_free_pages' and actual.kind == 'rebuild_temp')
        return (self.service.surface == 'sqlite_wal_free_pages' and resource.startswith('source:')
                or self.service.surface == 'execution_journal_payloads' and resource.startswith('source:execution'))

    def _advance(self, meter):
        from .c09_selected_history_v3 import _read_one, _bounded, record_selected_history_checkpoint_v3
        from .c09_storage_control_v1 import canonical
        from ..runtime_contracts import canonical_digest
        import json, stat
        view, service, control = self.view, self.service, self.service.control
        view.require_current(meter=meter)
        context = control.read_verified_current_storage_v3(meter=meter)
        if context.stage not in {'SWITCHED', 'CLEANED'} or context.prepared_original['operation_id'] != self.operation_id:
            raise AuthorityUnavailable('actual selected surface cleanup operation changed')
        if self.original is not None:
            return dict(status='complete', phase='surface_complete', original=self.original)
        if self.phase == 'schema':
            with control._db(write=True) as db:
                _install_surface_progress_schema_v3(control, db, meter)
            self.phase = 'inventory'
        elif self.phase == 'inventory':
            if self.inventory.advance(meter):
                self.phase = 'records'
        elif self.phase == 'records':
            if self.current_record is None:
                with control._db() as db:
                    row = _read_one(db, 'SELECT path_key,resource_id,path,commitment FROM c09_physical_inventory_records_v2 '
                        'WHERE stream_id=? AND pass_index=2 AND path_key>? ORDER BY path_key LIMIT 1',
                        (self.inventory.details['stream_id'], self.after), meter)
                if row is None:
                    self.phase = 'directory_roots'
                    return dict(status='progress', phase='surface_file_eof', surface=service.surface)
                if not self._selected_record(row):
                    self.after = row[0]
                    return dict(status='progress', phase='surface_inventory_record', surface=service.surface)
                self.current_record = row
            row = self.current_record;path = Path(row[2])
            with control._db() as db:
                plan = _bounded(db, meter).execute('SELECT plan_json FROM c09_surface_file_plans_v3 WHERE selection_digest=? AND resolved_path=?',
                    (view.basis.selection_digest, str(path))).fetchone()
                effect = _bounded(db, meter).execute('SELECT effect_json FROM c09_surface_file_effects_v3 WHERE selection_digest=? AND resolved_path=?',
                    (view.basis.selection_digest, str(path))).fetchone()
            if plan is not None:
                self.file_plan = json.loads(plan[0]);control.verify_original_v1(self.file_plan, 'plan_digest')
                planned = self.file_plan
                if (planned['selection_digest'] != view.basis.selection_digest or planned['resolved_path'] != str(path)
                        or planned['operation_id'] != self.operation_id or planned['manifest_digest'] != context.manifest_digest
                        or planned['source_inventory_original_digest'] != context.manifest['physical_inventory_complete_original_digest']):
                    raise AuthorityUnavailable('actual surface file plan scope differs')
                before = planned['before']
                role = row[1].split(':')[1] if row[1].startswith('source:') else None
                identity = (before['device'], before['file_id'], before['prepared_size'], before['prepared_mtime_ns'])
                if (before['resolved_path'] != str(path) or before['prepared_sha256'] is None
                        or canonical_digest(('file', identity, before['prepared_sha256'], planned['fragment_root'], role, row[1], str(path))) != row[3]):
                    raise AuthorityUnavailable('actual signed disposal plan does not match this frozen resource commitment')
            if effect is not None:
                original = json.loads(effect[0]);control.verify_original_v1(original, 'effect_digest')
                if (self.file_plan is None or original['selection_digest'] != view.basis.selection_digest
                        or original['operation_id'] != self.operation_id or original['resolved_path'] != str(path)
                        or original['plan_digest'] != self.file_plan['plan_digest']
                        or original['observation'] != dict(kind='removed_file', resolved_path=str(path), state='absent')):
                    raise AuthorityUnavailable('actual disposed file effect differs from its authenticated plan')
                try:path.lstat()
                except FileNotFoundError:pass
                else:raise AuthorityUnavailable('actually disposed surface file reappeared')
                self._adopt_removed(row, original['effect_digest']);return dict(status='progress', phase='surface_effect_replay')
            if plan is not None:
                before = self.file_plan['before']
            else:
                try:info = path.lstat()
                except FileNotFoundError:
                    role = row[1].split(':')[1] if row[1].startswith('source:') else None
                    if canonical_digest(('absent', row[1], str(path), role)) != row[3]:
                        raise AuthorityUnavailable('actual frozen surface file vanished without a signed disposal plan')
                    self.after = row[0];self.current_record = None
                    return dict(status='progress', phase='surface_registered_absence')
                if stat.S_ISDIR(info.st_mode):
                    if self.saved_original is None and canonical_digest(('directory', (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns), None, None, row[1], str(path))) != row[3]:
                        # Own earlier removals may change directory mtime; the inode is rechecked by the independent EOF walk.
                        if not row[1].startswith('registered:'):
                            raise AuthorityUnavailable('actual frozen nonregistered directory changed')
                    self.after = row[0];self.current_record = None
                    return dict(status='progress', phase='surface_registered_directory')
                if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise AuthorityUnavailable('actual surface entry is a symlink or unsupported inode')
                before = dict(resolved_path=str(path), device=info.st_dev, file_id=info.st_ino,
                    prepared_size=info.st_size, prepared_mtime_ns=info.st_mtime_ns, prepared_sha256=None)
            if service.surface == 'controlled_backups':
                from .d12_managed_backup_cleanup_v2 import VerifiedD12BackupCoverageV3
                coverage = service.require_selected_file_coverage_v3(before, view=view, meter=meter)
                if type(coverage) is not VerifiedD12BackupCoverageV3:
                    raise AuthorityUnavailable('actual complete private backup coverage required before file disposal')
                coverage.require_current(meter=meter)
            if self.file is None:
                from .c09_durable_unlink_v2 import InstalledDurableUnlinkProgressV3
                self.file = InstalledDurableUnlinkProgressV3(before)
                self.file_index = 0;self.file_fragment_root = '0' * 64
            if not self.file.verified:
                old_offset = self.file.offset
                if not self.file.advance(meter=meter):
                    self._fragment(old_offset, meter)
                    return dict(status='progress', phase='surface_file_hash', surface=service.surface, bytes_processed=self.file.offset)
                self._fragment(old_offset, meter)
            if self.file_plan is None:
                before = dict(self.file.before, prepared_sha256=self.file.hasher.hexdigest())
                role = row[1].split(':')[1] if row[1].startswith('source:') else None
                identity = (before['device'], before['file_id'], before['prepared_size'], before['prepared_mtime_ns'])
                if canonical_digest(('file', identity, before['prepared_sha256'], self.file_fragment_root, role, row[1], str(path))) != row[3]:
                    raise AuthorityUnavailable('actual surface file does not match complete frozen physical original')
                self.file.before = before
                self.file_plan = control.sign_original_v1('sylanne3.c09.surface-file-plan.v3', dict(
                    schema='sylanne3.c09.surface-file-plan.v3', selection_digest=view.basis.selection_digest,
                    operation_id=self.operation_id, manifest_digest=context.manifest_digest, source_inventory_original_digest=context.manifest['physical_inventory_complete_original_digest'],
                    resolved_path=str(path), frozen_commitment=row[3], fragment_root=self.file_fragment_root, before=before), 'plan_digest')
                with control._db(write=True) as db:
                    meter.write_row(db, 'c09_surface_file_plans_v3', ('selection_digest', 'resolved_path', 'plan_json', 'plan_digest'),
                        (view.basis.selection_digest, str(path), canonical(self.file_plan), self.file_plan['plan_digest']))
                return dict(status='progress', phase='surface_file_authorized', surface=service.surface)
            if not self.file.absent and self.file_fragment_root != self.file_plan['fragment_root']:
                raise AuthorityUnavailable('actual disposed file fragment coverage differs from signed plan')
            observation = self.file.finish(meter=meter);self.file = None
            effect = control.sign_original_v1('sylanne3.c09.surface-file-effect.v3', dict(schema='sylanne3.c09.surface-file-effect.v3',
                selection_digest=view.basis.selection_digest, operation_id=self.operation_id, resolved_path=str(path),
                plan_digest=self.file_plan['plan_digest'], observation=observation), 'effect_digest')
            with control._db(write=True) as db:
                meter.write_row(db, 'c09_surface_file_effects_v3', ('selection_digest', 'resolved_path', 'effect_json', 'effect_digest'),
                    (view.basis.selection_digest, str(path), canonical(effect), effect['effect_digest']))
            self._adopt_removed(row, effect['effect_digest'])
        elif self.phase == 'directory_roots':
            self.walker = InstalledManagedDirectoryReadV3(control, view, surface=service.surface,
                roots=service._roots(), protected=service._protected(context))
            self.phase = 'directory_scan'
        elif self.phase == 'directory_scan':
            if self.walker.advance(meter):
                self.directory_count, self.entry_count = self.walker.directory_count, self.walker.entry_count
                self.directory_root = self.walker.directory_root
                self.phase = 'observations'
        elif self.phase == 'observations':
            certificate = control._selected_execution_cleanup_certificate_v3
            control.verify_original_v1(certificate, 'checkpoint_digest')
            if certificate['details']['eof'] is not True or certificate['selection_digest'] != view.basis.selection_digest:
                raise AuthorityUnavailable('actual complete execution coverage is absent before surface evidence')
            observations = [dict(kind='managed_surface_directory_eof', directory_count=self.directory_count,
                inspected_entry_count=self.entry_count, directory_root=self.directory_root),
                dict(kind='durable_removed_file_eof', file_count=self.removed_count, removed_root=self.removed_root)]
            if service.surface in _GRAPH:
                graph = view.basis.member('graph')
                observations.append(dict(kind='selected_sanitized_graph_v3', resolved_path=graph['resolved_path'],
                    logical_data_root=graph['logical_data_root'], cold_read_digest=graph['cold_read_digest'],
                    incarnation=graph['incarnation_or_journal_id'], selected_history_root=view.history_root))
            if service.surface == 'execution_journal_payloads':
                observations.append(dict(kind='selected_execution_coverage_v3', checkpoint_digest=certificate['checkpoint_digest'],
                    execution_count=certificate['details']['count'], typed_recovery_root=certificate['details']['root']))
            if service.surface == 'process_local_caches':
                peer = service.gate._peer_retirement_coverage_v3
                peer.require_current(meter=meter)
                observations.append(dict(kind='actual_durable_peer_retirement_v3', completion_digest=peer.original['completion_digest'],
                    admission_count=peer.original['admission_count'], retirement_root=peer.original['retirement_root']))
            if self.saved_original is not None:
                saved = self.saved_original
                control.verify_original_v1(saved, 'evidence_digest')
                with control._db() as db:
                    row = _bounded(db, meter).execute('SELECT checkpoint_json FROM c09_selected_history_checkpoints_v3 WHERE checkpoint_digest=?',
                        (saved['plan_digest'],)).fetchone()
                if row is None:raise AuthorityUnavailable('actual surface completion original is absent')
                complete = json.loads(row[0]);control.verify_original_v1(complete, 'checkpoint_digest')
                details = complete['details']
                if (complete['selection_digest'] != view.basis.selection_digest or complete['consumer'] != 'surface_' + service.surface
                        or complete['operation_id'] != self.operation_id or complete['prepared_digest'] != context.prepared_original['prepared_digest']
                        or details['complete'] is not True or details['physical_record_count'] != self.inventory.count
                        or details['physical_record_root'] != self.inventory.record_root or details['removed_count'] != self.removed_count
                        or details['removed_root'] != self.removed_root or details['after_observations'] != observations
                        or saved['operation_id'] != self.operation_id or saved['manifest_digest'] != context.manifest_digest
                        or saved['surface'] != service.surface or saved['after_observations'] != observations):
                    raise AuthorityUnavailable('actual independent complete surface evidence differs')
                self.original = saved
                return dict(status='complete', phase='surface_independently_reread', original=saved)
            completion = record_selected_history_checkpoint_v3(view.basis, consumer='surface_' + service.surface, meter=meter,
                details=dict(schema='sylanne3.c09.surface-completion.v3', surface=service.surface,
                    physical_inventory_original_digest=context.manifest['physical_inventory_complete_original_digest'],
                    physical_record_count=self.inventory.count, physical_record_root=self.inventory.record_root,
                    physical_eof_digest=self.inventory.details['eof_observation_digest'], removed_count=self.removed_count,
                    removed_root=self.removed_root, directory_count=self.directory_count, directory_root=self.directory_root,
                    execution_coverage_original_digest=certificate['checkpoint_digest'], after_observations=observations, complete=True))
            self.original = control.sign_original_v1('sylanne3.c09.surface-evidence.v1', dict(
                schema='sylanne3.c09.surface-evidence.v1', installation_id=control.installation_id, issuer_id=control.authority_id,
                operation_id=self.operation_id, surface=service.surface, manifest_digest=context.manifest_digest,
                action='sanitized' if service.surface in _GRAPH else 'purged', plan_digest=completion['checkpoint_digest'],
                before_observations=[dict(kind='complete_frozen_inventory_v3', original_digest=context.manifest['physical_inventory_complete_original_digest'],
                    record_count=self.inventory.count, record_root=self.inventory.record_root)], after_observations=observations), 'evidence_digest')
            return dict(status='complete', phase='surface_complete', original=self.original)
        else:raise AuthorityUnavailable('actual surface progress private phase differs')
        return dict(status='progress', phase='surface_' + self.phase, surface=service.surface)

    def _fragment(self, offset, meter):
        from ..runtime_contracts import canonical_digest
        if self.file.offset == offset:return
        # The disposer retains the exact chunk digest, not its payload.
        self.file_fragment_root = canonical_digest((self.file_fragment_root, self.file_index, offset,
            self.file.offset - offset, self.file.last_chunk_digest))
        self.file_index += 1

    def _adopt_removed(self, row, effect_digest):
        from ..runtime_contracts import canonical_digest
        self.removed_count += 1
        self.removed_root = canonical_digest((self.removed_root, row[0].hex(), effect_digest))
        self.after = row[0];self.current_record = self.file_plan = None


def require_surface_progress_schema_v3(control, db):
    for table, ddl in (('c09_surface_file_plans_v3', _SURFACE_PLAN_DDL_V3), ('c09_surface_file_effects_v3', _SURFACE_EFFECT_DDL_V3),
                       ('c09_surface_directory_progress_v3', _SURFACE_FRONTIER_DDL_V3)):
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if row is None or row[0] != ddl:raise AuthorityUnavailable('actual surface progress schema differs')
        if table != 'c09_surface_directory_progress_v3':
            for action in ('UPDATE', 'DELETE'):
                row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (table + '_no_' + action.lower(),)).fetchone()
                if row is None or row[0] != control._immutable_ddl(table, action):
                    raise AuthorityUnavailable('actual surface disposal original is not immutable')
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_surface_effect_path_v3'").fetchone()
    if row is None or row[0] != _SURFACE_EFFECT_PATH_INDEX_V3:raise AuthorityUnavailable('actual surface effect path index differs')
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='c09_surface_directory_next_v3'").fetchone()
    if row is None or row[0] != _SURFACE_FRONTIER_INDEX_V3:raise AuthorityUnavailable('actual bounded directory frontier index differs')


class InstalledManagedDirectoryReadV3:
    """One actual directory entry per reserved call; every registered root reaches EOF."""
    def __init__(self, control, view, *, surface, roots, protected):
        from uuid import uuid4
        if view.basis.control is not control or surface not in SURFACES:
            raise AuthorityUnavailable('actual selected managed-directory reader required')
        self.control, self.view, self.surface = control, view, surface
        self.roots, self.protected, self.scan_id = tuple(roots), protected, uuid4().hex
        self.root_index = 0;self.directory = self.directory_row = self.directory_identity = None
        self.directory_count = self.entry_count = 0
        from ..runtime_contracts import canonical_digest
        self.directory_root = canonical_digest(('sylanne3.c09.surface-directories.v3', view.basis.selection_digest, surface))
        self.complete = False

    def close(self):
        if self.directory is not None:self.directory.close();self.directory = None

    def _enqueue(self, root, path, info, meter):
        from .c09_selected_history_v3 import _read_one
        with self.control._db(write=True) as db:
            args = (self.view.basis.selection_digest, self.surface, self.scan_id, str(path))
            prior = _read_one(db, 'SELECT root_path,device,file_id FROM c09_surface_directory_progress_v3 '
                'WHERE selection_digest=? AND surface=? AND scan_id=? AND directory_path=?', args, meter)
            if prior is None:
                meter.write_row(db, 'c09_surface_directory_progress_v3',
                    ('selection_digest','surface','scan_id','root_path','directory_path','device','file_id','scanned'),
                    (*args[:3], str(root), str(path), info.st_dev, info.st_ino, 0))
            elif prior[1:] != (info.st_dev, info.st_ino) or not path.is_relative_to(Path(prior[0])):
                raise AuthorityUnavailable('actual managed directory inode or registered root differs')

    def advance(self, meter):
        from .c09_selected_history_v3 import _read_one
        from ..runtime_contracts import canonical_digest
        self.view.require_current(meter=meter)
        if self.complete:return True
        if self.root_index < len(self.roots):
            root = _directory_path(self.roots[self.root_index]);info = root.stat()
            meter.charge_read(len(os.fsencode(root)) + 128)
            self._enqueue(root, root, info, meter);self.root_index += 1
            return False
        if self.directory is None:
            with self.control._db() as db:
                row = _read_one(db, 'SELECT root_path,directory_path,device,file_id FROM c09_surface_directory_progress_v3 '
                    'WHERE selection_digest=? AND surface=? AND scan_id=? AND scanned=0 ORDER BY directory_path COLLATE BINARY LIMIT 1',
                    (self.view.basis.selection_digest, self.surface, self.scan_id), meter)
            if row is None:self.complete = True;return True
            path = _directory_path(row[1]);info = path.stat()
            if (info.st_dev, info.st_ino) != row[2:]:raise AuthorityUnavailable('actual cleanup directory inode changed')
            self.directory_identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            self.directory_row = row;self.directory = os.scandir(path)
            return False
        entry = next(self.directory, None)
        if entry is None:
            row = self.directory_row;info = _directory_path(row[1]).stat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != self.directory_identity:
                raise AuthorityUnavailable('actual managed directory changed during complete independent enumeration')
            self.close()
            with self.control._db(write=True) as db:
                meter.write(db, 'UPDATE c09_surface_directory_progress_v3 SET scanned=1 '
                    'WHERE selection_digest=? AND surface=? AND scan_id=? AND directory_path=?',
                    (self.view.basis.selection_digest, self.surface, self.scan_id, row[1]))
            self.directory_count += 1
            self.directory_root = canonical_digest((self.directory_root, row[1], row[2], row[3]))
            return False
        meter.charge_read(len(os.fsencode(entry.path)) + 128)
        if entry.is_symlink():raise AuthorityUnavailable('actual cleaned directory contains a symlink')
        path = Path(entry.path).resolve(strict=True)
        if not path.is_relative_to(Path(self.directory_row[0])):
            raise AuthorityUnavailable('actual cleaned directory escaped its registered root')
        if entry.is_dir(follow_symlinks=False):
            self._enqueue(Path(self.directory_row[0]), path, entry.stat(follow_symlinks=False), meter)
        else:
            permitted = self.protected(path, meter) if callable(self.protected) else str(path) in self.protected
            if not permitted:raise AuthorityUnavailable('actual unretired bytes remain in managed directory')
        self.entry_count += 1
        return False
