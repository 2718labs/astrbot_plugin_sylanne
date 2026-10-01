"""Resume an earlier signed INTENT through actual source maintenance handles.

This runs before the ordinary Core constructor. It owns no business admission,
does not reconstruct an old close receipt and cannot replace partial targets.
"""
from contextlib import closing
from dataclasses import asdict, replace
import hashlib
import os
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable
from .c09_connection_state_v1 import anchor_in_tx_v1, namespace_row_in_tx_v1
from .c09_storage_control_v1 import file_observation_v1
from ..runtime_contracts import canonical_digest, canonical_serialize


class ColdC09SourceConnectionsV1:
    """The real four-store maintenance handles and their actual close completions."""
    def __init__(self, *, control):
        from .v2_deletion_guard import AuthorityV2DeletionGuard
        from .v2_fence_store import AuthorityV2FenceStore
        self.control = control
        self.members = {m["role"]: m for m in control.read_verified_current_storage_v1().manifest["members"]}
        self.connections, self.closed = {}, []
        self.deletion = None
        self.sealed = False
        try:
            for role in ("core", "execution", "graph"):
                path = Path(self.members[role]["resolved_path"])
                db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
                self.connections[role] = db
                db.execute("PRAGMA synchronous=FULL")
            self.deletion = AuthorityV2DeletionGuard(Path(self.members["deletion"]["resolved_path"]))
            self.connections["deletion"] = self.deletion._db
            AuthorityV2FenceStore._check_schema(self.connections["core"])
            self.fences = AuthorityV2FenceStore(self.connections["core"], create=False)
            self.checkpoint()
            self.close_role("graph")
            path = Path(self.members["graph"]["resolved_path"])
            self._require_closed(path)
            graph = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)
            graph.execute("PRAGMA query_only=ON")
            self.connections["graph"] = graph
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _require_closed(path):
        from .current_filesystem_inventory_v3 import _absent
        for suffix in ("-wal", "-shm", "-journal"):
            _absent(str(path) + suffix)

    def begin(self):
        for role, db in self.connections.items():
            db.execute("BEGIN" if role == "graph" or self.sealed else "BEGIN IMMEDIATE")

    def commit(self):
        for db in self.connections.values():
            db.commit()

    def checkpoint(self):
        for role, db in self.connections.items():
            if db.in_transaction:
                raise AuthorityUnavailable("C09 source checkpoint has active transaction")
            if db.execute("PRAGMA query_only").fetchone() == (1,):
                continue
            result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if result is not None and result[0] != 0:
                raise AuthorityUnavailable("C09 actual source checkpoint remains busy")

    def close_role(self, role):
        db = self.connections.get(role)
        if db is None:
            return
        path = db.execute("PRAGMA database_list").fetchone()[2]
        proof = dict(handle_type="sqlite3.Connection", connection_id=id(db), path=path,
            process_id=os.getpid(), thread_id=threading.get_ident())
        if role == "deletion" and self.deletion._db is db:
            self.deletion.close()
        else:
            db.close()
        self.closed.append(proof)
        del self.connections[role]

    def close(self):
        for role in tuple(self.connections):
            self.close_role(role)

    def seal_for_candidate_reads(self):
        """Finish all lawful source writes before any source fingerprint is retained."""
        self.commit(); self.checkpoint()
        for role in ("core", "execution", "deletion"):
            self.close_role(role)
            path = Path(self.members[role]["resolved_path"])
            self._require_closed(path)
            db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)
            db.execute("PRAGMA query_only=ON")
            self.connections[role] = db
        self.sealed = True


def _targets_with_complete_originals(control, operation, targets):
    """A physical partial candidate is never a cold replay credential."""
    for role, name in targets.items():
        path = Path(name)
        complete = control.read_build_original_v1(operation_id=operation,
            kind="graph_candidate" if role == "graph" else "file_" + role)
        allocation = control.read_build_original_v1(operation_id=operation, kind="allocation_" + role)
        if complete is not None and (not path.is_file() or allocation is None):
            raise AuthorityUnavailable("C09 completed target allocation absent")
        if not path.exists():
            if allocation is not None:
                raise AuthorityUnavailable("C09 allocated target disappeared")
            continue
        info = path.stat()
        if allocation is not None and (allocation["details"]["target_path"] != str(path)
                or (allocation["details"]["device"], allocation["details"]["file_id"]) != (info.st_dev, info.st_ino)):
            raise AuthorityUnavailable("C09 actual allocated target inode changed")
        if info.st_size and complete is None:
            raise AuthorityUnavailable("C09 nonempty partial target has no complete original")
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise AuthorityUnavailable("C09 candidate has unfinished companions")


def _read_source_gate(sources, *, config, context, operation):
    from .current_source_location_v1 import read_current_storage_lineage_v1, read_graph_location_in_tx_v1, require_current_source_anchor_in_tx_v1
    from .current_accepted_erasure_read import read_current_accepted_erasure_in_tx_v1
    from .erasure_closure_inventory import AuthorityErasureClosureInventory, CleanupRunV2, SurfaceRegistryV1, SURFACES_V1, _TABLES
    from .v2_fence_store import AuthorityV2FenceStore
    from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
    control, factory = sources.control, config.c09_maintenance_factory
    namespace = context.manifest["cohort_namespaces"][0]
    manifests, prepared, locations, commitments = read_current_storage_lineage_v1(
        control, context, namespace=namespace, installation_id=control.installation_id)
    core_db, graph = sources.connections["core"], sources.connections["graph"]
    AuthorityErasureClosureInventory._require_schema(core_db)
    run = AuthorityErasureClosureInventory._read_record(core_db, _TABLES[1], operation, CleanupRunV2)
    registry = AuthorityErasureClosureInventory._read_record(core_db, _TABLES[0], namespace, SurfaceRegistryV1)
    if (run is None or registry is None or registry.authority_id != control.authority_id
            or registry.namespace != namespace or registry.installation_id != control.installation_id
            or run.authority_id != control.authority_id or run.namespace != namespace
            or run.registry_digest != registry.registry_digest):
        raise AuthorityUnavailable("C09 actual accepted run/installed registry absent or changed")
    target = registry.targets[SURFACES_V1.index("execution_journal_payloads")]
    if (target.resource_kind != "sqlite_execution_journal" or target.inventory_state != "installed"
            or (target.target_ref, target.generation_ref) not in locations):
        raise AuthorityUnavailable("C09 actual registry execution ancestry differs")
    current = anchor_in_tx_v1(core_db, namespace)
    installed = config.installations_v2[factory.peer]
    row, _ = require_current_source_anchor_in_tx_v1(core_db, namespace=namespace,
        expected_anchor=current, holder=installed.administrator_holder)
    reader = C09ExecutionOriginalsConnectionV1(db=sources.connections["execution"], control=control, namespace=namespace)
    head, _ = reader.read_verified_rows_v1()
    deletion = sources.deletion.verified_head()
    if ((current.execution_journal_id, current.execution_seq, current.execution_digest) != (head.journal_id, head.seq, head.digest)
            or (current.deletion_journal_id, current.deletion_seq, current.deletion_digest) != (deletion.journal_id, deletion.seq, deletion.digest)
            or (run.execution_journal_id, run.execution_seq, run.execution_digest) != (head.journal_id, head.seq, head.digest)):
        raise AuthorityUnavailable("C09 actual independent journal/Core/run heads differ")
    fences = sources.fences
    mutation = fences.mutation_locked(core_db, run.accepted_mutation_id)
    if mutation is None:
        raise AuthorityUnavailable("C09 actual accepted mutation absent")
    _, _, receipt, _ = fences._decode_mutation_row(mutation)
    fence = fences._row(core_db, receipt.pending.permit.operation_id)
    if fence is None:
        raise AuthorityUnavailable("C09 accepted fence absent")
    permit = fences._permit(fence)
    if permit.holder != row[0] or permit.generation != current.activation_generation:
        raise AuthorityUnavailable("C09 actual accepted fence holder/generation differs")
    subject = "mtls:sha256:" + factory.peer[0]
    accepted = read_current_accepted_erasure_in_tx_v1(core_db, deletion=sources.deletion,
        fences=fences, namespace=namespace, subject=subject, installation_id=control.installation_id,
        deletion_operation_id=operation, scope_digest="sha256:" + run.scope_digest, permit=permit, current=current)
    if (accepted.accepted_receipt != receipt or canonical_digest(receipt) != run.accepted_receipt_digest
            or receipt.pending.evidence.proof_digest != "sha256:" + run.graph_barrier_receipt_digest
            or receipt.pending.evidence.barrier_scope_digest != "sha256:" + run.barrier_scope_digest):
        raise AuthorityUnavailable("C09 actual accepted run/barrier originals differ")
    metadata, epoch, incarnations = read_graph_location_in_tx_v1(graph, namespace_id=factory.namespace,
        namespace=namespace, purpose="accepted_erasure", anchor=current, accepted_receipt=receipt,
        manifests=manifests, prepared=prepared)
    location = dict(purpose="accepted_erasure", namespace_id=factory.namespace,
        authority_namespace=namespace, installation_id=control.installation_id,
        graph_db_path=sources.members["graph"]["resolved_path"], current_graph_metadata=metadata,
        graph_epoch=epoch, core_anchor=current, holder=row[0], graph_incarnations=incarnations,
        execution_locations=locations, selected_files=tuple((m["role"], m["resolved_path"], m["device"], m["file_id"], m["incarnation_or_journal_id"]) for m in context.manifest["members"]),
        storage_ancestors=tuple((m["generation"], v["role"], v["resolved_path"], v["store_id"], v["namespace"], m["installation_id"], v["incarnation_or_journal_id"], v["device"], v["file_id"]) for m in manifests for v in m["members"]),
        lineage_commitments=commitments, pointer_version=context.pointer_version,
        manifest_digest=context.manifest_digest, storage_generation=context.storage_generation,
        stage=context.stage, control_operation_id=operation, subject=subject, permit=permit,
        accepted_receipt=receipt, context_commitment=(context.control_path, context.pointer_version,
            context.manifest_digest, context.storage_generation, context.stage,
            canonical_digest(context.manifest), canonical_digest(context.prepared_original)))
    return reader, run, accepted, location


def _graph_candidate(control, *, operation, target, source, request, registry):
    from .c09_build_originals_v1 import decode_installed_build_original_v1
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, build_graph_rebase_candidate_v1, _file_identity, _cold_graph_data_root
    saved = control.read_build_original_v1(operation_id=operation, kind="graph_candidate")
    if saved is None:
        return build_graph_rebase_candidate_v1(source, target, request=request, completion_control=control, registry=registry)
    candidate = decode_installed_build_original_v1(saved["details"]["candidate"], GraphRebaseCandidateV1)
    if ((candidate.operation_id, candidate.namespace, candidate.source_path, candidate.target_path,
            candidate.source_files_fingerprint, candidate.source_closure_digest, candidate.frozen_inventory_digest,
            candidate.writer_freeze_digest, candidate.affected_atom_refs, candidate.source_identity) !=
            (operation, request.namespace, str(source), str(target), request.source_files_fingerprint,
            request.certified_closure_digest, request.frozen_inventory_digest, request.writer_freeze_digest,
            request.affected_atom_refs, _file_identity(source))):
        raise AuthorityUnavailable("C09 completed Graph candidate source/input changed")
    mirror = control.read_build_original_v1(operation_id=operation, kind="graph_mirror")
    if mirror is None:
        if (_file_identity(target) != candidate.target_identity
                or hashlib.sha256(target.read_bytes()).hexdigest() != candidate.new_file_sha256):
            raise AuthorityUnavailable("C09 completed Graph candidate physical proof changed")
    root, cold = _cold_graph_data_root(target, candidate.namespace, set(candidate.affected_atom_refs),
        candidate.new_incarnation, candidate.cumulative_erased_key_digests, registry=registry)
    if (root, cold) != (candidate.certificate_draft.new_data_root, candidate.certificate_draft.cold_read_digest):
        raise AuthorityUnavailable("C09 actual Graph candidate independent cold proof differs")
    return candidate


def _final_scan(sources, *, control, gate, continuation, current, operation, location, inventory, graph_candidate, candidate):
    from .c09_final_inventory_v3 import read_source_roots_v3
    from .c09_authority_storage_rebase import _identity, _files_sha
    from .current_filesystem_inventory_v3 import derive_current_inventory_mappings_v3, _observe_inventory_paths_v3, verify_current_inventory_evidence_v3, SCHEMA
    from ..runtime.c09_graph_rebase_candidate_v1 import graph_source_files_fingerprint_v1
    from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemScanV2
    sources.commit(); sources.checkpoint()
    members = current.manifest["members"]
    roots = read_source_roots_v3(members, installation_id=control.installation_id, lease=control.lease, closed=False)
    before = {m["role"]: [file_observation_v1(Path(m["resolved_path"] + suffix), exclusive=True)
        for suffix in ("", "-wal", "-shm", "-journal") if Path(m["resolved_path"] + suffix).exists()] for m in members}
    links = {"graph": asdict(graph_candidate)}
    if (graph_source_files_fingerprint_v1(Path(graph_candidate.source_path)) != graph_candidate.source_files_fingerprint
            or _identity(Path(graph_candidate.source_path)) != graph_candidate.source_identity):
        raise AuthorityUnavailable("C09 final Graph candidate source changed")
    for role in ("core", "execution", "deletion"):
        original = getattr(candidate, role)
        if (_identity(Path(original.source_path)) != original.source_identity
                or _files_sha(Path(original.source_path)) != original.source_files_sha256
                or roots[role]["application_rows_root"] != original.source_data_root):
            raise AuthorityUnavailable("C09 final candidate source differs")
        links[role] = asdict(original)
    sources.begin()
    from .current_source_location_v1 import require_current_source_anchor_in_tx_v1, require_graph_source_snapshot_in_tx_v1
    require_current_source_anchor_in_tx_v1(sources.connections["core"], namespace=location["authority_namespace"],
        expected_anchor=location["core_anchor"], holder=location["holder"])
    require_graph_source_snapshot_in_tx_v1(sources.connections["graph"], namespace_id=location["namespace_id"],
        expected_metadata=location["current_graph_metadata"], expected_epoch=location["graph_epoch"])
    sources.commit(); sources.close()
    after_roots = read_source_roots_v3(members, installation_id=control.installation_id, lease=control.lease, closed=True)
    if after_roots != roots:
        raise AuthorityUnavailable("C09 actual close changed rows/schema/persistent metadata")
    after = {m["role"]: [file_observation_v1(m["resolved_path"], exclusive=True)] for m in members}
    mappings = derive_current_inventory_mappings_v3(inventory, storage_ancestors=location["storage_ancestors"],
        storage_generation=current.storage_generation)
    observed, coverage, retired = _observe_inventory_paths_v3(mappings, inventory.resources)
    rows = tuple(observed[path] for path in sorted(observed))
    schema = "sylanne3.c09.installation_filesystem_scan.v2"
    scan = InstallationFilesystemScanV2(inventory.manifest_digest, rows,
        canonical_digest((schema, inventory.manifest_digest, rows)), schema)
    view = dict(schema="sylanne3.c09.current-filesystem-view.v3", original_manifest=asdict(inventory),
        location=location, mappings=tuple(asdict(mapping) for mapping in mappings))
    quiescence = gate.require_final_continuation_v3(continuation, operation_id=operation)
    body = dict(schema=SCHEMA, view=view, view_digest=canonical_digest(view), scan=asdict(scan),
        retired_absence=tuple(sorted(retired)), directory_coverage=tuple(sorted(coverage)),
        closed_predecessor=dict(operation_id=operation, accepted_receipt_digest=canonical_digest(location["accepted_receipt"]),
            pointer_version=current.pointer_version, manifest_digest=current.manifest_digest,
            quiescence_original=quiescence, logical_roots=roots, before_physical=before, after_physical=after,
            candidate_source_originals=links, candidate_digest=candidate.candidate_digest,
            graph_candidate_digest=graph_candidate.candidate_digest, closed_connections=tuple(sources.closed),
            continuous_exclusion=dict(operation_id=operation, admission_epoch=continuation[2], thread_id=continuation[3],
                lease_path=str(control.lease.path), process_id=os.getpid())))
    result = verify_current_inventory_evidence_v3({**body, "scan_digest": canonical_digest(body)})
    control.record_build_original_v1(operation_id=operation, kind="current_inventory_scan_v3", details=result)
    return result, quiescence


def resume_early_intent_before_open_v1(*, config, control):
    from .c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
    from .c09_retired_final_scan_v1 import _retirement
    from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
    from .deployment_config import ExecutionJournalInstallation
    from .daemon import _preflight
    from .c09_source_prepare_v4 import prepare_execution_source_connections_v4
    from .c09_graph_rebase_issue_v1 import issue_graph_rebase_in_tx_v1, read_graph_rebase_issue_original_v1
    from .c09_authority_storage_rebase import build_authority_storage_rebase_connections_v1
    from .c09_contact_policy_rows_v1 import verify_contact_policy_source_in_tx_v1
    from .c09_prepared_assembly_v1 import assemble_prepared_storage_v1
    from .c09_retired_prepared_marker_v1 import verify_retired_prepared_marker_v1
    from .current_filesystem_inventory_v3 import reread_closed_inventory_v3
    from ..runtime.c09_graph_rebase_candidate_v1 import derive_graph_rebase_input_in_tx_v1, install_graph_rebase_certificate_connection_v1
    from ..runtime.c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1
    current = control.read_verified_current_storage_v1()
    if current.stage != "INTENT" or type(config.c09_maintenance_factory) is not InstalledC09MaintenanceFactoryV1:
        raise AuthorityUnavailable("C09 early continuation needs actual INTENT and installed maintenance assets")
    factory = config.c09_maintenance_factory
    namespace = current.manifest["cohort_namespaces"][0]
    installed = config.installations_v2.get(factory.peer)
    if (installed is None or installed.installation_id != control.installation_id
            or factory.inventory.installation_id != control.installation_id
            or factory.inventory.authority_id != control.authority_id
            or config.namespace_bindings_v2.get((*factory.peer, factory.namespace)) != namespace):
        raise AuthorityUnavailable("C09 cold factory differs from actual installed namespace/peer")
    with control._db() as db:
        operation = control._current(db)["active_operation_id"]
    intent = control.read_operation_event_v1(operation, "INTENT")
    _retirement(control, intent["details"]["quiescence_original"])
    if (intent["details"]["old_manifest_digest"] != current.manifest_digest
            or intent["details"]["expected_pointer_version"] != current.pointer_version
            or factory.inventory.manifest_digest != current.manifest["inventory_manifest_digest"]):
        raise AuthorityUnavailable("C09 signed INTENT pointer/installed manifest differs")
    members = {m["role"]: m for m in current.manifest["members"]}
    selected = replace(config, authority_db=Path(members["core"]["resolved_path"]),
        deletion_db=Path(members["deletion"]["resolved_path"]), graph_db=Path(members["graph"]["resolved_path"]),
        execution_journals={namespace: ExecutionJournalInstallation(Path(members["execution"]["resolved_path"]), members["execution"]["incarnation_or_journal_id"])})
    _preflight(selected)
    _targets_with_complete_originals(control, operation, intent["details"]["targets"])
    gate = InstalledC09WriterGateV1(control=control)
    control._final_gate_v3 = gate
    gate.revoke_and_drain_v1(operation_id=operation)
    with gate.hold_final_continuation_v3(operation_id=operation) as continuation:
        sources = ColdC09SourceConnectionsV1(control=control)
        try:
            sources.begin()
            reader, run, accepted, location = _read_source_gate(sources, config=selected, context=current, operation=operation)
            _qualify_provider_scopes(sources.connections["core"], control=control, factory=factory,
                namespace=namespace, operation=operation)
            verify_contact_policy_source_in_tx_v1(sources.connections["core"], config=selected, control=control, namespace=namespace)
            bundle = prepare_execution_source_connections_v4(core_db=sources.connections["core"],
                business_db=sources.connections["graph"], execution_reader=reader, config=selected,
                control=control, operation_id=operation, run=run, accepted=accepted.accepted_receipt)
            sources.commit(); sources.checkpoint(); sources.begin()
            request = derive_graph_rebase_input_in_tx_v1(sources.connections["graph"],
                source_path=Path(members["graph"]["resolved_path"]), namespace=factory.namespace,
                operation_id=operation, installation_id=control.installation_id, accepted=accepted,
                pinned_manifest_digest=factory.inventory.manifest_digest,
                writer_freeze_digest=intent["details"]["quiescence_original"]["quiescence_digest"])
            graph = _graph_candidate(control, operation=operation, target=Path(intent["details"]["targets"]["graph"]),
                source=Path(members["graph"]["resolved_path"]), request=request, registry=factory.registry)
            core_db = sources.connections["core"]
            prior_issue = read_graph_rebase_issue_original_v1(core_db, namespace, operation_id=operation)
            if prior_issue is None and control.read_build_original_v1(operation_id=operation, kind="file_core") is not None:
                raise AuthorityUnavailable("C09 completed Core candidate forbids a new source Graph issue")
            issue = issue_graph_rebase_in_tx_v1(core_db, key=control._key,
                manifest=factory.inventory, candidate=graph, run=run, pin=bundle["pin"])
            sources.commit(); sources.checkpoint(); sources.begin()
            mirror = install_graph_rebase_certificate_connection_v1(graph, core_db=core_db,
                signing_key=control._key, inventory_manifest=factory.inventory,
                completion_control=control, issued=issue, registry=factory.registry)
            sources.seal_for_candidate_reads(); sources.begin()
            core_db = sources.connections["core"]
            from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
            reader = C09ExecutionOriginalsConnectionV1(db=sources.connections["execution"], control=control, namespace=namespace)
            candidate, bindings, transition, issue = build_authority_storage_rebase_connections_v1(
                core_db=core_db, execution_db=sources.connections["execution"], deletion_db=sources.connections["deletion"],
                execution_reader=reader, control=control, namespace=namespace, installation_id=control.installation_id,
                inventory_manifest=factory.inventory, operation_id=operation, graph_mirror=mirror,
                targets=intent["details"]["targets"], bundle=bundle)
            barrier = read_c09_erasure_barrier_v1(sources.connections["graph"], factory.namespace, operation)
            checkpoint = dict(schema="sylanne3.c09.prepared_checkpoint_inputs.v1", namespace=namespace,
                operation_id=operation, old_anchor=asdict(location["core_anchor"]), transition=transition,
                accepted_receipt=asdict(bundle["accepted_receipt"]), accepted_receipt_digest=canonical_digest(bundle["accepted_receipt"]),
                barrier=asdict(barrier), barrier_digest=canonical_digest(barrier), facts_pin=asdict(bundle["pin"]),
                facts_digest=bundle["facts"].facts_digest, bindings_digest=bindings.bindings_digest,
                issue=asdict(issue), inventory=asdict(factory.inventory), graph_mirror=asdict(mirror),
                candidate_digest=candidate.candidate_digest, graph_candidate_digest=graph.candidate_digest)
            control.record_build_original_v1(operation_id=operation, kind="prepared_checkpoint_inputs_v1", details=checkpoint)
            sources.commit()
            verify_retired_prepared_marker_v1(core_path=Path(candidate.core.target_path), source_core_path=Path(candidate.core.source_path),
                execution_path=Path(candidate.execution.target_path), namespace=namespace, operation_id=operation,
                expected_pin_digest=bundle["pin"].pin_digest, expected_issue_digest=issue.issue_digest,
                expected_new_journal_id=candidate.new_execution_journal_id, maintenance_generation=current.storage_generation + 1)
            scan, quiescence = _final_scan(sources, control=control, gate=gate, continuation=continuation,
                current=current, operation=operation, location=location, inventory=factory.inventory,
                graph_candidate=graph, candidate=candidate)
            manifest, prepared = assemble_prepared_storage_v1(control=control, current=current, operation_id=operation,
                graph_candidate=graph, graph_mirror=mirror, candidate=candidate, checkpoint=checkpoint, scan=scan,
                quiescence=quiescence)
            reread_closed_inventory_v3(scan)
            gate.require_final_continuation_v3(continuation, operation_id=operation)
            control.record_prepared_storage_v1(manifest=manifest, prepared_original=prepared, closing_continuation=continuation)
        finally:
            sources.close()
    return control.read_verified_current_storage_v1()


def _qualify_provider_scopes(db, *, control, factory, namespace, operation):
    from .v2_model_egress_store import _decoded
    present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone()
    rows = () if present is None else tuple(db.execute(
        "SELECT call_id,operation_id,namespace,subject,identity_json FROM authority_model_egress_v1 WHERE namespace=?", (namespace,)))
    scopes, commitments = set(), []
    for call, item_operation, item_namespace, subject, payload in rows:
        intent = _decoded(payload)
        if (intent.call_id, intent.operation_id, intent.namespace, intent.subject) != (call, item_operation, item_namespace, subject):
            raise AuthorityUnavailable("C09 real historical provider original differs")
        scopes.add((intent.provider_id, intent.provider_config_digest))
        commitments.append(canonical_digest((call, item_operation, item_namespace, subject, payload)))
    cleaner = factory.provider_cache_cleanup
    if scopes:
        if {scope[0] for scope in scopes} != {getattr(cleaner, "provider_id", None)}:
            raise AuthorityUnavailable("C09 installed cache cleaner does not cover real historical providers")
        cleaner.require_historical_provider_scopes_v2(tuple(sorted(scopes)))
    control.record_build_original_v1(operation_id=operation, kind="provider_scope_inventory",
        details={"schema": "sylanne3.c09.historical-provider-scopes.v2", "namespace": namespace,
            "installation_id": control.installation_id, "provider_config_scopes": sorted(scopes),
            "source_row_commitments": sorted(commitments)})
