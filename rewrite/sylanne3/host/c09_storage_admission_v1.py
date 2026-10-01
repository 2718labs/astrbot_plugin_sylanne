"""Local Linux C09 admission from the independently installed Authority.

A root-owned Unix socket authenticates both OS processes. The caller cannot
supply a PID, generation or Graph path, and cannot upgrade its old admission.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import stat
import struct

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.linux_installation_security_v1 import read_installed_json_v1
from ..authority_service.c09_process_identity_v1 import read_process_identity_v1


@dataclass(frozen=True, slots=True)
class InstalledHostStorageAdmissionV1:
    installation_id: str
    authority_id: str
    pointer_version: int
    storage_generation: int
    manifest_digest: str
    graph_path: Path
    process_original: dict
    lifecycle_bootstrap: dict | None = None
    package_selection: object | None = None
    package_bootstrap: dict | None = None

    def require_current_process_v1(self):
        if read_process_identity_v1(os.getpid()) != self.process_original:
            raise AuthorityUnavailable("C09 Host admission belongs to another process")


def load_installed_host_storage_v1(profile_id, bundle):
    if os.name != "posix":
        return None
    profile_root = Path("/etc/sylanne/client/profiles") / profile_id
    path = profile_root / "c09-storage.json"
    if not path.exists():
        return None
    config = read_installed_json_v1(path, limit=8192)
    if (set(config) != {"schema", "socket_path", "installation_id", "authority_id", "host_uid"}
            or config["schema"] != "sylanne3.c09.host-storage-admission.v1"
            or config["installation_id"] != bundle.installation_policy.installation_id
            or config["authority_id"] != bundle.installation_policy.expected_authority_id
            or config["host_uid"] != os.geteuid() or os.geteuid() == 0):
        raise AuthorityUnavailable("C09 Host installation scope differs")
    endpoint = Path(config["socket_path"])
    if not endpoint.is_absolute():
        raise AuthorityUnavailable("C09 local socket path must be installed")
    # Protect every parent from endpoint replacement. Socket itself must be root
    # owned; peer credentials below recheck the actual connected server.
    for parent in (endpoint.parent, *endpoint.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AuthorityUnavailable("C09 local socket parent is unsafe")
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        raise AuthorityUnavailable("C09 local admission socket is unsafe")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(10)
        channel.connect(str(endpoint))
        pid, uid, _gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0 or pid < 1:
            raise AuthorityUnavailable("C09 local Authority process is not privileged")
        request = {"schema": "sylanne3.c09.host-admission-request.v1", "profile_id": profile_id,
            "installation_id": config["installation_id"], "authority_id": config["authority_id"]}
        selected = getattr(bundle, 'package_selection', None)
        if selected is not None:
            from dataclasses import asdict
            request['schema'] = 'sylanne3.c09.host-admission-request.v2'
            request['package_selection'] = asdict(selected)
        channel.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        with channel.makefile("rb") as stream:
            raw = stream.readline(16385)
        if len(raw) > 16384 or not raw.endswith(b"\n"):
            raise AuthorityUnavailable("C09 admission response exceeds limit")
    result = json.loads(raw)
    if result.get("status") != "admitted":
        raise AuthorityUnavailable("C09 current Host admission is unavailable")
    fields = {"schema", "status", "profile_id", "installation_id", "authority_id", "pointer_version",
              "storage_generation", "manifest_digest", "graph_path", "process_original", "lifecycle_bootstrap"}
    schema = 'sylanne3.c09.host-admission.v2' if selected is not None else 'sylanne3.c09.host-admission.v1'
    if selected is not None: fields.update({'package_selection','package_bootstrap'})
    if (set(result) != fields or result["schema"] != schema
            or result["profile_id"] != profile_id or result["installation_id"] != config["installation_id"]
            or result["authority_id"] != config["authority_id"]
            or type(result["pointer_version"]) is not int or result["pointer_version"] < 0
            or type(result["storage_generation"]) is not int or result["storage_generation"] < 0
            or len(result["manifest_digest"]) != 64):
        raise AuthorityUnavailable("C09 admission response identity differs")
    if selected is not None:
        from ..authority_service.d12_package_files_v2 import decode_package_selection_v2
        if decode_package_selection_v2(result['package_selection']) != selected:
            raise AuthorityUnavailable('independent Host admission selected cohort differs')
    bootstrap = result["lifecycle_bootstrap"]
    if bootstrap is not None:
        from uuid import UUID
        if (type(bootstrap) is not dict or set(bootstrap) != {"operation_id", "expected_epoch", "invocation_id"}
                or type(bootstrap["expected_epoch"]) is not int or bootstrap["expected_epoch"] < 1
                or type(bootstrap["invocation_id"]) is not str or len(bootstrap["invocation_id"]) != 32
                or any(c not in "0123456789abcdef" for c in bootstrap["invocation_id"])
                or str(UUID(bootstrap["operation_id"])) != bootstrap["operation_id"] or UUID(bootstrap["operation_id"]).version != 4):
            raise AuthorityUnavailable("exact resume bootstrap identity required")
    package_bootstrap=result.get('package_bootstrap')
    if package_bootstrap is not None:
        expected={'operation_id','maintenance_phase','lifecycle_epoch','package_epoch','selection_revision','cohort_digest',
            'selection_digest','process_original','invocation_id','state'}
        from uuid import UUID
        if (selected is None or bootstrap is not None or type(package_bootstrap) is not dict or set(package_bootstrap)!=expected
                or package_bootstrap['state']!='bootstrap_only'
                or package_bootstrap['maintenance_phase'] not in {'forward','rollback','abort_before_switch'}
                or package_bootstrap['maintenance_phase']!='abort_before_switch' and package_bootstrap['operation_id']!=selected.operation_id
                or package_bootstrap['package_epoch']!=selected.package_epoch or package_bootstrap['selection_revision']!=selected.revision
                or package_bootstrap['cohort_digest']!=selected.cohort_digest or package_bootstrap['selection_digest']!=selected.selection_digest
                or package_bootstrap['process_original']!=result['process_original']
                or type(package_bootstrap['lifecycle_epoch']) is not int or package_bootstrap['lifecycle_epoch']<1
                or type(package_bootstrap['invocation_id']) is not str or len(package_bootstrap['invocation_id'])!=32
                or any(c not in '0123456789abcdef' for c in package_bootstrap['invocation_id'])
                or UUID(package_bootstrap['operation_id']).version!=4):
            raise AuthorityUnavailable('exact current package bootstrap admission required')
    graph = Path(result["graph_path"])
    if not graph.is_absolute() or graph.is_symlink() or not graph.is_file():
        raise AuthorityUnavailable("C09 current Graph path is unavailable")
    admission = InstalledHostStorageAdmissionV1(result["installation_id"], result["authority_id"],
        result["pointer_version"], result["storage_generation"], result["manifest_digest"],
        graph, result["process_original"], bootstrap, selected, package_bootstrap)
    admission.require_current_process_v1()
    return admission


def require_current_selected_host_admission_v2(admission, bundle, package_root):
    """Actual Unix-admitted current process plus independently reread selection."""
    if type(admission) is not InstalledHostStorageAdmissionV1:
        raise AuthorityUnavailable('actual installed Host storage admission required')
    admission.require_current_process_v1()
    from .selected_profile_cohort_v2 import require_current_bundle_selection_v2
    selected = require_current_bundle_selection_v2(bundle, package_root, require_selected_python=True)
    if selected is None or admission.package_selection != selected:
        raise AuthorityUnavailable('actual Host admission has no matching current selected cohort')
    return selected
