"""Registered, streamed draft-file adapter on the existing D11 Life authority.

The caller is the installed Authority Life service with an already durable
claim. This module creates no permission, claim, journal or budget store. Its
readback is part of the admitted execution; a later observation needs the
separate observation request/admission in the closed recipe contract.
"""
from contextlib import contextmanager
import ctypes
import hashlib
import os
from pathlib import Path
import stat
import time

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import _directory_path
from .v2_contract import FencePermitV2
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
from ..runtime.d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from ..runtime.d11_artifact_draft_contract_v1 import (
    CHUNK_BYTES, RegisteredDraftFilePlanV3, DraftFileIdentityV1, DraftFileReadbackV1,
)
from ..runtime.d11_offline_originals_v1 import _utc


class DraftFileEffectUncertain(AuthorityUnavailable):
    """Preserve real work/possible handoff for the existing signed terminal path."""
    def __init__(self, reason, *, handoff_started, actual_cpu_ms, readback=None):
        super().__init__(reason)
        self.handoff_started = handoff_started
        self.actual_cpu_ms = actual_cpu_ms
        self.readback = readback


def read_current_draft_content_chunks_v1(db, *, frame, plan):
    """Actual D06 closure and exact frozen Source text, at most 64 KiB per chunk.

    Graph Source qualification is one input to the independent final-source
    fence admission; it does not replace that Authority arbitration. Existing
    Source text bounds remain unchanged. A registered larger artifact provider
    must be installed explicitly before other content kinds can be consumed.
    """
    if type(plan) is not RegisteredDraftFilePlanV3:
        raise TypeError("registered draft plan required")
    reader = CurrentDomainReadV1(frame)
    reader.check(db)
    content = plan.content
    key = AtomKey.from_token(content.content.ref)
    if key.type_name != "memory.source":
        raise MissingProductionOriginalV1("current_registered_draft_content_provider:" + key.type_name)
    if key.token not in content.source_refs:
        raise ValueError("draft content is absent from its qualified Source lineage")
    records = None
    for audience in plan.audiences:
        records = reader.source_family(db, content.source_refs, purpose=frame.envelope.authority.purpose, audience=audience)
    atom = reader.head(db, key, required=True)
    if atom.revision != content.content.revision or canonical_digest(atom.value) != content.content.digest:
        raise AuthorityUnavailable("draft frozen content Source revision/digest changed")
    text = records[key.token].text
    hasher, length = hashlib.sha256(), 0
    # Each Unicode scalar consumes at most four UTF-8 bytes. The existing
    # bounded Source is already in the pinned frame; no second full byte copy.
    for offset in range(0, len(text), CHUNK_BYTES // 4):
        block = text[offset:offset + CHUNK_BYTES // 4].encode("utf-8")
        length += len(block)
        if length > min(content.content_length, plan.target.max_bytes):
            raise AuthorityUnavailable("draft content exceeded its exact frozen byte bound")
        hasher.update(block)
        yield block
    if (length, hasher.hexdigest()) != (content.content_length, content.content_digest):
        raise AuthorityUnavailable("draft content bytes differ from frozen length/hash")


@contextmanager
def _pinned_root(path, expected):
    """Pin the exact directory; Windows also pins ancestors against rename."""
    path = _directory_path(path)
    handles = []
    descriptor = None
    try:
        if os.name == "nt":
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            for parent in reversed((path, *path.parents)):
                handle = kernel.CreateFileW(str(parent), 0x80000000, 3, None, 3, 0x02200000, None)
                if handle == wintypes.HANDLE(-1).value:
                    raise AuthorityUnavailable("draft registered directory handle unavailable")
                handles.append(handle)
            root_stat = path.stat(follow_symlinks=False)
        else:
            descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            for part in path.parts[1:]:
                current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = current
            root_stat = os.fstat(descriptor)
        if DraftFileIdentityV1(root_stat.st_dev, root_stat.st_ino) != expected:
            raise AuthorityUnavailable("draft registered root OS identity changed")
        _directory_path(path)
        yield path, descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if handles:
            for handle in reversed(handles):
                kernel.CloseHandle(handle)


def _readback(path, *, expected_length, expected_digest, expected_identity=None, directory_fd=None, read_meter=None, body_capture=None):
    """Same-handle content/identity observation with the recipe's chunk bound."""
    from .c09_storage_control_v1 import _regular_path
    path = Path(path)
    if directory_fd is None:
        path = _regular_path(path)
    if os.name == "nt":
        from ctypes import wintypes
        import msvcrt
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise AuthorityUnavailable("draft actual readback handle unavailable")
        final = ctypes.create_unicode_buffer(32768)
        if not kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0):
            kernel.CloseHandle(handle)
            raise AuthorityUnavailable("draft readback final path unavailable")
        normalized = final.value
        if normalized.startswith("\\\\?\\UNC\\"):
            normalized = "\\\\" + normalized[8:]
        elif normalized.startswith("\\\\?\\"):
            normalized = normalized[4:]
        if os.path.normcase(normalized) != os.path.normcase(str(path)):
            kernel.CloseHandle(handle)
            raise AuthorityUnavailable("draft readback opened another actual path")
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    else:
        descriptor = (os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC) if directory_fd is None
            else os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or getattr(before, "st_file_attributes", 0) & 0x400):
            raise AuthorityUnavailable("draft readback requires one real regular target without aliases")
        identity = DraftFileIdentityV1(before.st_dev, before.st_ino)
        if before.st_size != expected_length:
            raise AuthorityUnavailable("draft readback metadata length differs before reading body bytes")
        if expected_identity is not None and identity != expected_identity:
            raise AuthorityUnavailable("draft readback found another same-name file identity")
        hasher, length = hashlib.sha256(), 0
        while length < expected_length:
            block = stream.read(min(CHUNK_BYTES, expected_length - length))
            if not block:
                break
            length += len(block)
            if read_meter is not None:
                read_meter[0] += len(block)
            if length > expected_length:
                raise AuthorityUnavailable("draft readback exceeds frozen length")
            hasher.update(block)
            if body_capture is not None:
                body_capture.extend(block)
        after = os.fstat(stream.fileno())
        if ((before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
                or (length, hasher.hexdigest()) != (expected_length, expected_digest)):
            raise AuthorityUnavailable("draft actual readback bytes changed")
    return identity


def _resource(service, inventory, plan):
    if (type(inventory) is not InstallationFilesystemManifestV2
            or (inventory.authority_id, inventory.installation_id, inventory.namespace) !=
               (service.bridge.core._id(service.bridge.core._db), service.installation_id, service.bridge.namespace)):
        raise AuthorityUnavailable("draft inventory differs from actual Authority installation")
    storage = service.bridge.journal._installed_storage_reader
    if storage is None:
        raise AuthorityUnavailable("draft requires the actual independent C09 current-storage reader")
    context = storage.read_verified_current_storage_v1()
    context.require_current("business")
    if context.manifest["inventory_manifest_digest"] != inventory.manifest_digest:
        raise AuthorityUnavailable("draft root is absent from the current signed storage inventory")
    roots = tuple(r for r in inventory.resources if r.resource_id == plan.target.root_resource_id)
    if (len(roots) != 1 or roots[0].kind != "export"
            or not {"jobs_drafts", "imports_exports"} <= set(roots[0].content_coverage)):
        raise AuthorityUnavailable("draft requires its separately registered export carrier")
    return roots[0]


def _predecessor(root, plan, directory_fd):
    target = root / plan.target.filename
    if plan.target.mode == "create":
        try:
            os.stat(target if directory_fd is None else target.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise AuthorityUnavailable("draft create predecessor is no longer absent")
    else:
        expected = plan.target.expected_prior_identity
        previous = os.stat(target if directory_fd is None else target.name, dir_fd=directory_fd, follow_symlinks=False)
        _readback(target, expected_length=previous.st_size,
            expected_digest=plan.target.expected_prior_digest, expected_identity=expected, directory_fd=directory_fd)
    return target


def execute_claimed_artifact_draft_v1(service, *, prepared, claim, frame, content_db,
        current_read_permit, inventory_manifest):
    """Perform only an original installed Life claim, never execute an observation.

    Shared Life preparation must authenticate V3 activity/root capability,
    previous effect/version, and independent current Source grant under the
    same final-admission arbitration. This adapter reuses its current reader
    again before handoff. Unsupported shared V3 preparation fails before I/O.
    The returned byte witness is signed/journaled by the existing Life service.
    """
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if type(service) is not AuthorityD11LifeServiceV1 or type(prepared.plan) is not RegisteredDraftFilePlanV3:
        raise AuthorityUnavailable("actual installed Life service and typed V3 preparation required")
    if type(current_read_permit) is not FencePermitV2:
        raise AuthorityUnavailable("draft handoff needs its actual currently admitted Source read permit")
    plan, binding = prepared.plan, prepared.binding
    service._binding(binding)
    if (binding.plan_digest != plan.digest or binding.effect_id != plan.effect_id
            or binding.operation_id != plan.operation_id
            or current_read_permit.namespace != binding.authority_namespace
            or current_read_permit.authority_id != binding.authority_id
            or current_read_permit.generation != binding.activation_generation):
        raise AuthorityUnavailable("draft handoff crossed frozen plan/Authority/Source permit")
    if (not content_db.in_transaction or content_db.execute("PRAGMA query_only").fetchone() != (1,)
            or Path(content_db.execute("PRAGMA database_list").fetchone()[2]).resolve() != service.graph_path):
        raise AuthorityUnavailable("draft content requires actual pinned readonly installed Graph")
    start = time.thread_time_ns()
    handoff, readback = False, None
    temporary_path, temporary_owned = None, False
    try:
        with service._execution_lock:
            actual_claim, terminal = service.read_d11_life_original_v1(binding)
            if actual_claim != claim or terminal is not None or claim.payload.prepared_digest != prepared.digest:
                raise AuthorityUnavailable("draft original claim is absent, changed or already terminal")
            service._verify_payload(claim.payload)
            if service._prepared(binding, permit=current_read_permit) != prepared:
                raise AuthorityUnavailable("draft current preparation changed before handoff")
            with service._frozen() as (core_db, deletion, execution, _):
                anchor, _ = service._current(core_db, deletion, execution)
                service.fences.validate_fence_locked(core_db, current_read_permit,
                    subject=service._subject, current_anchor=anchor)
                service.require_current_draft_source_in_tx_v1(core_db, binding)
                resource = _resource(service, inventory_manifest, plan)
            deadline = min(_utc(plan.deadline_utc).timestamp(), _utc(binding.job_lease_expires_utc).timestamp())
            if service._now() >= deadline:
                raise AuthorityUnavailable("draft original deadline expired before staging")
            with _pinned_root(resource.path, plan.target.root_identity) as (root, directory_fd):
                try:
                    target = _predecessor(root, plan, directory_fd)
                    temporary = ".draft-" + canonical_digest((binding.authority_namespace, plan.effect_id, plan.digest)) + ".pending"
                    temporary_path = root / temporary
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                    descriptor = (os.open(temporary_path, flags, 0o600) if directory_fd is None
                        else os.open(temporary, flags, 0o600, dir_fd=directory_fd))
                    temporary_owned = True
                    with os.fdopen(descriptor, "wb") as stream:
                        for block in read_current_draft_content_chunks_v1(content_db, frame=frame, plan=plan):
                            if service._now() >= deadline:
                                raise AuthorityUnavailable("draft original deadline expired during staging")
                            stream.write(block)
                        stream.flush()
                        os.fsync(stream.fileno())
                        staged = os.fstat(stream.fileno())
                        staged_identity = DraftFileIdentityV1(staged.st_dev, staged.st_ino)
                    _readback(temporary_path, expected_length=plan.content.content_length,
                        expected_digest=plan.content.content_digest, expected_identity=staged_identity, directory_fd=directory_fd)
                    # This is a current check of the original authority, not a new
                    # effect or a refreshed deadline/claim. Source revocation and
                    # stop after admission can still race the actual handoff.
                    if service._prepared(binding, permit=current_read_permit) != prepared:
                        raise AuthorityUnavailable("draft original scope cancelled before handoff")
                    with service._frozen() as (core_db, deletion, execution, _):
                        anchor, _ = service._current(core_db, deletion, execution)
                        service.fences.validate_fence_locked(core_db, current_read_permit,
                            subject=service._subject, current_anchor=anchor)
                        service.require_current_draft_source_in_tx_v1(core_db, binding)
                    if service._now() >= deadline:
                        raise AuthorityUnavailable("draft original deadline expired before handoff")
                    _predecessor(root, plan, directory_fd)
                    handoff_at = service._utc_text(service._now())
                    handoff = True
                    if plan.target.mode == "create":
                        if directory_fd is None:
                            os.link(temporary_path, target, follow_symlinks=False)
                        else:
                            os.link(temporary, plan.target.filename, src_dir_fd=directory_fd,
                                dst_dir_fd=directory_fd, follow_symlinks=False)
                        os.unlink(temporary_path if directory_fd is None else temporary, dir_fd=directory_fd)
                    elif directory_fd is None:
                        os.replace(temporary_path, target)
                    else:
                        os.replace(temporary, plan.target.filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    temporary_path, temporary_owned = None, False
                    if directory_fd is not None:
                        os.fsync(directory_fd)
                    identity = _readback(target, expected_length=plan.content.content_length,
                        expected_digest=plan.content.content_digest, expected_identity=staged_identity, directory_fd=directory_fd)
                    end = service._utc_text(service._now())
                    cpu = (time.thread_time_ns() - start + 999999) // 1000000
                    marker = canonical_digest(("d11.artifact-draft-effect.v1", binding.namespace,
                        plan.effect_id, plan.execution_call_id, plan.digest, plan.target.digest,
                        plan.target.expected_prior_version + 1, identity, plan.content.content_digest))
                    readback = DraftFileReadbackV1(plan.effect_id, plan.execution_call_id, plan.digest,
                        plan.target.digest, plan.target.root_registration_digest, plan.target.filename,
                        plan.target.expected_prior_version + 1, plan.content.content_digest, plan.content.content_length,
                        identity, marker, handoff_at, end, cpu)
                    if service._now() >= deadline or cpu > plan.cpu_ceiling_ms:
                        raise AuthorityUnavailable("draft actual handoff/readback exceeded original time or CPU ceiling")
                    return readback
                finally:
                    if temporary_owned and temporary_path is not None:
                        os.unlink(temporary_path if directory_fd is None else temporary, dir_fd=directory_fd)
                        temporary_path, temporary_owned = None, False
    except Exception as exc:
        cpu = (time.thread_time_ns() - start + 999999) // 1000000
        raise DraftFileEffectUncertain(str(exc), handoff_started=handoff, actual_cpu_ms=cpu, readback=readback) from exc
