"""Actual installed resource domain for the C09 V2 physical census."""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

from contextlib import contextmanager
import json
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import ROLES
from .c09_prepared_storage_v2 import _build_original
from ..runtime_contracts import canonical_digest

_BOUND = object()


class InstalledC09PhysicalInventoryBoundV2:
    __slots__ = ("_issuer", "session", "control", "scope_digest", "source_domain_digest", "_headers",
        "_role_readers_v3", "_role_proofs_v3", "_role_index_v3", "_publication_result_v3", "actual_core_role")

    def __init__(self, token, session, headers, actual_core_role):
        if token is not _BOUND:
            raise AuthorityUnavailable("actual installed physical inventory binding required")
        self._issuer, self.session = token, session
        self.control = session._control.maintenance.control
        self.scope_digest = session.scope.scope_digest
        self._headers = headers
        self.actual_core_role = actual_core_role
        self._role_readers_v3 = {}
        self._role_proofs_v3 = {}
        self._role_index_v3 = 0
        self._publication_result_v3 = None
        self.source_domain_digest = canonical_digest((
            "sylanne3.c09.physical-resource-domain.v2", session.scope,
            session._control.maintenance.inventory_manifest.manifest_digest,
            tuple((role,headers[role][0]) for role in ROLES)))

    def require_current(self):
        if self._issuer is not _BOUND:
            raise AuthorityUnavailable("physical inventory binding issuer differs")
        self.session.require_current()
        m = self.session._control.maintenance
        m.gate.require_final_continuation_v3(m._c09_final_continuation_v2,
            operation_id=self.session.scope.operation_id)
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2, C09PagedCaptureHold, C09SqlByteMeterV2, c09_sql_meter_quantum_v2
        try:
            meter = current_c09_sql_meter_v2()
        except C09PagedCaptureHold:
            with self.control.reserve_control_read_v3() as budget:
                meter = require_c09_reserved_meter_v3(budget)
                with c09_sql_meter_quantum_v2(meter):
                    return self.require_current()
        from .c09_paged_recovery_facts_v2 import _read_one
        with self.control._db() as db:
            for role in ROLES:
                expected, header = self._headers[role]
                actual = _read_one(db, "SELECT original_digest FROM c09_storage_build_originals_v1 "
                    "WHERE installation_id=? AND operation_id=? AND original_kind=?",
                    (self.control.installation_id, self.session.scope.operation_id, "capture_role_complete_v2_" + role), meter)
                if actual != (expected,):
                    raise AuthorityUnavailable("physical inventory actual immutable completed role changed")
        return self

    @contextmanager
    def metadata_transaction(self):
        self.require_current()
        with self.control._db(write=True) as db:
            self.control._current(db)
            yield db
        self.require_current()

    def reserve_batch(self):
        return self.session.reserve_batch()

    def next_root(self, after_resource_id, meter):
        """Return one registered root; the caller never supplies its pathname."""
        self.require_current()
        after = "" if after_resource_id is None else after_resource_id
        m = self.session._control.maintenance
        selected = None
        def consider(item):
            nonlocal selected
            if item["resource_id"] > after and (selected is None or item["resource_id"] < selected["resource_id"]):
                selected = item
        for resource in m.inventory_manifest.resources:
            if resource.kind in {"controlled_backup", "export", "rebuild_temp", "cache"}:
                consider(dict(resource_id="registered:"+resource.resource_id, path=resource.path,
                    kind="directory", expected_identity=None, expected_sha256=None, role=None))
        for role in ROLES:
            header = self._headers[role][1]
            source = header["source_original"]
            identity = json.loads(source["source_identity"])
            source_identity = tuple(identity[name] for name in ("device", "file_id", "size", "mtime_ns"))
            for stage, path, inode, sha in (
                    ("source", source["source_path"], source_identity, source["source_file_sha256"]),
                    ("target", header["target_path"], tuple(header["target_file_identity"] if role != "graph" else header["target_identity"]), header["target_sha256"])):
                consider(dict(resource_id=stage+":"+role, path=path, kind="file",
                    expected_identity=inode, expected_sha256=sha, role=role))
                for suffix in ("-wal", "-shm", "-journal"):
                    consider(dict(resource_id=stage+":"+role+":"+suffix, path=path+suffix,
                        kind="absent", expected_identity=None, expected_sha256=None, role=role))
        # Historical role files are selected one manifest at a time. Each
        # manifest has exactly four members; no complete ancestry is expanded.
        generation = int(after.split(":",2)[1]) if after.startswith("retired:") else 0
        with self.control._db() as db:
            for query_index in range(2):
                row = db.execute("SELECT generation,manifest_digest,length(CAST(manifest_json AS BLOB)) FROM c09_storage_manifests_v1 WHERE installation_id=? AND generation>=? AND generation<? ORDER BY generation LIMIT 1",
                    (self.control.installation_id,generation,self.session.scope.maintenance_generation-1)).fetchone()
                if row is None:
                    break
                meter.charge_read(len(row[1].encode("utf-8"))+16)
                meter.require_available(row[2]*4)
                meter.charge_read(row[2])
                manifest = self.control._read_manifest(db,row[1])
                found = False
                for member in manifest["members"]:
                    for suffix in ("", "-wal", "-shm", "-journal"):
                        item = dict(resource_id=f"retired:{row[0]:020d}:{member['role']}:{suffix}",
                            path=member["resolved_path"]+suffix, kind="absent", expected_identity=None,
                            expected_sha256=None, role=member["role"])
                        if item["resource_id"] > after:
                            found = True
                        consider(item)
                if found:
                    break
                generation = row[0] + 1
        return selected


def bind_current_physical_inventory_v2(session, *, actual_core_role):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    if type(session) is not C09PagedCaptureSessionV2:
        raise AuthorityUnavailable("actual installed C09 session required")
    session.require_current()
    from .c09_authority_storage_rebase_v2 import VerifiedAuthorityRoleRebaseV2
    if (type(actual_core_role) is not VerifiedAuthorityRoleRebaseV2 or actual_core_role.role != 'core'
            or actual_core_role.scope != session.scope or actual_core_role.builder.session is not session):
        raise AuthorityUnavailable('actual current private completed Core role required for publication')
    actual_core_role.require_current()
    m = session._control.maintenance
    headers = {}
    with m.control._db() as db:
        from .c09_paged_recovery_facts_v2 import _read_one
        from .c09_prepared_storage_v3 import _read_original
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
        for role in ROLES:
            kind = "capture_role_complete_v2_" + role
            row = _read_one(db, "SELECT original_digest FROM c09_storage_build_originals_v1 "
                "WHERE installation_id=? AND operation_id=? AND original_kind=?",
                (m.control.installation_id, session.scope.operation_id, kind), meter)
            if row is None:
                raise AuthorityUnavailable("actual complete physical inventory role absent: " + role)
            details = _read_original(m.control, db, session.scope.operation_id, kind, row[0], meter)
            if details["scope_digest"] != session.scope.scope_digest:
                raise AuthorityUnavailable("physical inventory crosses actual completed scope")
            headers[role] = (row[0], details)
    bound = InstalledC09PhysicalInventoryBoundV2(_BOUND, session, headers, actual_core_role)
    return bound.require_current()


def record_current_physical_inventory_v2(bound, verified):
    """Sign only the actual same-bound complete two-pass physical census."""
    from .c09_physical_inventory_stream_v2 import VerifiedPhysicalInventoryV2
    if type(bound) is not InstalledC09PhysicalInventoryBoundV2 or type(verified) is not VerifiedPhysicalInventoryV2:
        raise AuthorityUnavailable("actual installed complete physical inventory required")
    bound.require_current()
    verified.require_current()
    if verified._progress.bound is not bound or verified.source_domain_digest != bound.source_domain_digest:
        raise AuthorityUnavailable("physical inventory completion belongs to another resource domain")
    scope=bound.session.scope
    details=dict(schema="sylanne3.c09.frozen-physical-inventory-complete.v2",
        scope_digest=scope.scope_digest,source_domain_digest=bound.source_domain_digest,
        installation_inventory_digest=bound.session._control.maintenance.inventory_manifest.manifest_digest,
        stream_id=verified.stream_id,record_count=verified.record_count,page_count=verified.page_count,
        record_root=verified.record_root,page_root=verified.page_root,
        eof_observation_digest=verified.eof_observation_digest,
        four_role_complete_original_digests={role:bound._headers[role][0] for role in ROLES},
        accepted_receipt_digest=scope.accepted_receipt_digest,
        barrier_digest=scope.barrier_digest,writer_freeze_digest=scope.writer_freeze_digest)
    original=bound.control.record_build_original_v1(operation_id=scope.operation_id,
        kind="frozen_inventory_complete_v2",details=details)
    verified.require_current()
    bound.require_current()
    return original


def begin_current_physical_inventory_v2(session, *, actual_core_role):
    """Create the genuine resource binding inside its installed reservation."""
    from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
    from .c09_control_paged_schema_v2 import install_paged_control_schema_v2
    from .c09_physical_inventory_stream_v2 import begin_physical_inventory_v2
    with session.reserve_batch() as budget:
        meter = require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            bound = bind_current_physical_inventory_v2(session, actual_core_role=actual_core_role)
            with bound.control._db(write=True) as db:
                bound.control._current(db)
                install_paged_control_schema_v2(session._control, db, meter)
            return begin_physical_inventory_v2(bound)


def advance_current_physical_inventory_v2(progress):
    """Advance one installed reserved quantum using the same parent meter."""
    from .c09_physical_inventory_stream_v2 import PhysicalInventoryProgressV2, advance_physical_inventory_v2
    from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
    if type(progress) is not PhysicalInventoryProgressV2:
        raise AuthorityUnavailable("actual installed physical inventory progress required")
    bound=progress.bound
    if type(bound) is not InstalledC09PhysicalInventoryBoundV2:
        raise AuthorityUnavailable("actual installed resource bound required")
    bound.require_current()
    with bound.reserve_batch() as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            return advance_physical_inventory_v2(progress,budget,meter)


def advance_current_prepared_publication_v3(bound, physical, *, closing_continuation):
    """One role-original quantum, then one same-gate actual V3 publication."""
    from .c09_physical_inventory_stream_v2 import VerifiedPhysicalInventoryV2
    from .c09_prepared_storage_v3 import begin_segmented_role_original_read_v3, VerifiedSegmentedRoleOriginalV3
    from ..runtime.c09_paged_sql_v2 import C09SqlByteMeterV2, c09_sql_meter_quantum_v2
    if type(bound) is not InstalledC09PhysicalInventoryBoundV2 or type(physical) is not VerifiedPhysicalInventoryV2:
        raise AuthorityUnavailable('actual installed publication bound and complete physical inventory required')
    session = bound.session
    session._control._registered()
    with bound.control.reserve_control_read_v3() as budget:
        meter = require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            session.require_current()
            bound.require_current()
            physical.require_current()
            session._control.maintenance.gate.require_final_continuation_v3(closing_continuation,
                operation_id=session.scope.operation_id, observe=False)
            if bound._publication_result_v3 is not None:
                return bound._publication_result_v3
            if bound._role_index_v3 < len(ROLES):
                role = ROLES[bound._role_index_v3]
                if role not in bound._role_readers_v3:
                    bound._role_readers_v3[role] = begin_segmented_role_original_read_v3(bound.control,
                        scope=session.scope, role=role, base_complete_original_digest=bound._headers[role][0])
                result = bound._role_readers_v3[role].advance(meter=meter)
                if type(result) is VerifiedSegmentedRoleOriginalV3:
                    bound._role_proofs_v3[role] = result
                    bound._role_index_v3 += 1
                return {'status': 'progress', 'phase': 'prepared_segmented_role_originals', 'role': role}
            from .c09_prepared_assembly_v2 import assemble_current_prepared_storage_v2
            result = assemble_current_prepared_storage_v2(bound, physical,
                closing_continuation=closing_continuation,
                verified_roles=tuple(bound._role_proofs_v3[role] for role in ROLES),
                verified_core_obligations=bound.actual_core_role.builder.natural_core_obligations_proof_v4)
    bound._publication_result_v3 = result
    return result
