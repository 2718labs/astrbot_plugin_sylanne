"""Root-owned OS admission and stopped-service C09 Host retirement."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess

from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
from .linux_installation_security_v1 import require_linux_administrator_v1


class InstalledLinuxHostSupervisorV1:
    def __init__(self, *, daemon, socket_path, host_uid, host_gid, systemd_unit):
        require_linux_administrator_v1()
        if (type(host_uid) is not int or host_uid < 1 or type(host_gid) is not int or host_gid < 1
                or type(systemd_unit) is not str or not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", systemd_unit)
                or daemon.c09_gate is None):
            raise AuthorityUnavailable("installed non-root systemd Host identity required")
        self.daemon, self.path = daemon, Path(socket_path)
        self.uid, self.gid, self.unit = host_uid, host_gid, systemd_unit
        self.listener = None
        daemon.c09_gate.install_peer_retirement_handler_v1(self.retire_peers_v1)

    def _systemctl(self, *arguments):
        result = subprocess.run(["/usr/bin/systemctl", *arguments, self.unit],
            capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if result.returncode:
            raise AuthorityUnavailable("installed Host systemd operation failed")
        return result.stdout.strip()

    def retire_peers_v1(self, originals):
        # systemd stops the whole service control group, including descendant
        # workers. Never send a signal to an unchecked caller-supplied PID.
        self._systemctl("stop")
        if self._systemctl("show", "--property=MainPID", "--value") != "0":
            raise AuthorityUnavailable("installed Host main process remains live")
        return tuple(require_process_retired_v1(original) for original in originals)

    async def _admit(self, reader, writer):
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5)
            if len(raw) > 8192:
                raise AuthorityUnavailable("Host admission request exceeds bound")
            request = json.loads(raw)
            fields = {"schema", "profile_id", "installation_id", "authority_id"}
            selected_request = request.get('schema') == 'sylanne3.c09.host-admission-request.v2'
            if (set(request) != fields | ({'package_selection'} if selected_request else set())
                    or request['schema'] not in {'sylanne3.c09.host-admission-request.v1','sylanne3.c09.host-admission-request.v2'}):
                raise AuthorityUnavailable("Host admission schema differs")
            pid, uid, _gid = struct.unpack("3i", writer.get_extra_info("socket").getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != self.uid:
                raise AuthorityUnavailable("Host admission OS principal differs")
            # MainPID establishes the installed service, not merely another
            # process sharing the user's UID. Spawned workers use separate grants.
            actual_pid = await asyncio.to_thread(self._systemctl, "show", "--property=MainPID", "--value")
            if actual_pid != str(pid):
                raise AuthorityUnavailable("Host admission is not the installed service process")
            matches = [(peer, installation) for peer, installation in self.daemon.config.installations_v2.items()
                       if peer[1] == request["profile_id"] and installation.installation_id == request["installation_id"]]
            if len(matches) != 1 or request["authority_id"] != self.daemon.c09_control.authority_id:
                raise AuthorityUnavailable("Host admission installation differs")
            bundle_matches = tuple(item.installation_bundle for item in self.daemon.config.natural_model_authorities_v2.values()
                if item.observer_peer == matches[0][0])
            if len(bundle_matches) != 1:
                raise AuthorityUnavailable('actual installed Host profile bundle required')
            bundle = bundle_matches[0]
            selected = bundle.package_selection
            if selected_request != (selected is not None):
                raise AuthorityUnavailable('Host selected-cohort admission protocol differs')
            if selected is not None:
                from .d12_package_files_v2 import decode_package_selection_v2
                from ..host.selected_profile_cohort_v2 import require_current_bundle_selection_v2
                if (decode_package_selection_v2(request['package_selection']) != selected
                        or getattr(self.daemon.server, '_package_selection_v2', None) != selected
                        or matches[0][1].manifest_digest != selected.manifest_sha256):
                    raise AuthorityUnavailable('Host and running Authority selected cohorts differ')
                await asyncio.to_thread(require_current_bundle_selection_v2,bundle,Path(__file__).absolute().parents[3],
                    require_selected_python=True,authority_private_config=True)
            context = self.daemon.c09_control.read_verified_current_storage_v1()
            context.require_current("business")
            from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
            lifecycle_services = tuple(service for service in getattr(self.daemon.server,
                "_d12_installation_lifecycle_services_v1", {}).values()
                if service.peer == matches[0][0] and service.installation_id == request["installation_id"])
            lifecycle_bootstrap = None
            package_bootstrap = None
            if len(lifecycle_services) != 1:
                raise AuthorityUnavailable("installed Host lifecycle admission is absent or ambiguous")
            service = lifecycle_services[0]
            with service.core._tx() as db:
                head = read_lifecycle_head_in_tx_v1(db, service.namespace)
                package_operation = None
                if selected is not None:
                    from .d12_package_maintenance_authority_v2 import HEADS
                    package_operation = db.execute(f'SELECT operation_id FROM {HEADS} WHERE namespace=? AND operation_id=?',
                        (service.namespace, head.operation_id if head is not None else None)).fetchone()
                if head is None or head.state not in {'active','resuming','quiescing','drained'}:
                    raise AuthorityUnavailable('current lifecycle does not admit a Host')
                if head.state != 'active' and package_operation is None:
                    if head.state != 'resuming':raise AuthorityUnavailable('current lifecycle does not admit an ordinary Host')
                    row = service._operation(db, head.operation_id)
                    if row[13] not in {'start_intent','ready'}:
                        raise AuthorityUnavailable('resume has no original process start intent')
                    service._owner_still_current(db,row)
                    lifecycle_bootstrap = {'operation_id':head.operation_id,'expected_epoch':head.epoch}
            if head.state != 'active' and package_operation is not None:
                from .mtls_server import MtlsPeerCredential
                package_service = getattr(self.daemon.server,'_d12_package_services_v2',{}).get(service.namespace)
                if package_service is None or selected is None:
                    raise AuthorityUnavailable('actual package bootstrap service absent')
                observed = await asyncio.to_thread(service.supervisor.read_current_host_state_v1)
                package_bootstrap = await asyncio.to_thread(package_service.read_current_maintenance_bootstrap_v2,
                    credential=MtlsPeerCredential(matches[0][0][0]),process_id=pid,invocation_id=observed.invocation_id,
                    selection_revision=selected.revision,cohort_digest=selected.cohort_digest)
            if lifecycle_bootstrap is not None:
                observed = await asyncio.to_thread(service.supervisor.read_current_host_state_v1)
                if observed.main_pid != pid or pid not in observed.process_ids or observed.active_state != 'active':
                    raise AuthorityUnavailable('resume Host is not the installed active invocation')
                lifecycle_bootstrap['invocation_id'] = observed.invocation_id
            original = read_process_identity_v1(pid)
            if original is None:
                raise AuthorityUnavailable("Host process exited before admission")
            self.daemon.c09_gate.register_peer_process_v1(peer=matches[0][0], process_id=pid,
                process_incarnation="linux-host:" + original["birth"], pointer_version=context.pointer_version,
                storage_generation=context.storage_generation)
            member = next(item for item in context.manifest["members"] if item["role"] == "graph")
            result = {"schema": "sylanne3.c09.host-admission.v1", "status": "admitted", **{key: request[key]
                for key in ("profile_id", "installation_id", "authority_id")},
                "pointer_version": context.pointer_version, "storage_generation": context.storage_generation,
                "manifest_digest": context.manifest_digest, "graph_path": member["resolved_path"],
                "process_original": original, "lifecycle_bootstrap": lifecycle_bootstrap}
            if selected is not None:
                from dataclasses import asdict
                result['schema'] = 'sylanne3.c09.host-admission.v2'
                result['package_selection'] = asdict(selected)
                result['package_bootstrap'] = package_bootstrap
        except Exception:
            result = {"status": "hold"}
        try:
            writer.write(json.dumps(result, separators=(",", ":")).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def start(self):
        # Only this generation's Graph directory is delegated to the Host.
        # Core and both independent journals must be under other parents.
        context = self.daemon.c09_control.read_verified_current_storage_v1()
        graph = Path(next(item["resolved_path"] for item in context.manifest["members"] if item["role"] == "graph"))
        if any(Path(item["resolved_path"]).parent == graph.parent for item in context.manifest["members"] if item["role"] != "graph"):
            raise AuthorityUnavailable("Host Graph directory overlaps protected Authority journals")
        if graph.is_symlink() or graph.parent.is_symlink():
            raise AuthorityUnavailable("Host Graph path changed")
        os.chown(graph.parent, 0, self.gid)
        os.chmod(graph.parent, 0o770)
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(graph) + suffix)
            if path.exists():
                if not path.is_file() or path.is_symlink():
                    raise AuthorityUnavailable("Host Graph companion changed")
                os.chown(path, self.uid, self.gid)
                os.chmod(path, 0o600)
        parent = self.path.parent
        if not self.path.is_absolute() or not parent.is_dir():
            raise AuthorityUnavailable("installed admission socket directory unavailable")
        for component in (parent, *parent.parents):
            info = component.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise AuthorityUnavailable("installed admission socket directory is unsafe")
        if self.path.exists():
            info = self.path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                raise AuthorityUnavailable("unexpected existing admission endpoint")
            # The Authority instance OS lease is already held. No live prior
            # daemon is permitted; remove its stale named socket only.
            self.daemon.c09_control.lease.require_held()
            self.path.unlink()
        self.listener = await asyncio.start_unix_server(self._admit, path=str(self.path), limit=8193)
        os.chown(self.path, 0, self.gid)
        os.chmod(self.path, 0o660)

    async def start_host(self):
        from .d12_lifecycle_gate_v1 import read_lifecycle_head_in_tx_v1
        services = tuple(getattr(self.daemon.server, "_d12_installation_lifecycle_services_v1", {}).values())
        if len(services) != 1:
            raise AuthorityUnavailable("actual single-cohort lifecycle controller required before Host start")
        service = services[0]
        with service.core._tx() as db:
            head = read_lifecycle_head_in_tx_v1(db, service.namespace)
            if head is None:
                raise AuthorityUnavailable("durable installed lifecycle head required")
            if head.state != "active":
                # Only the original durable resume worker owns start_intent.
                # A paused or ambiguous restart must never auto-start Host.
                return False
        await asyncio.to_thread(self._systemctl, "start", "--no-block")
        return True

    async def aclose(self):
        if self.listener is not None:
            self.listener.close()
            await self.listener.wait_closed()
            self.listener = None
