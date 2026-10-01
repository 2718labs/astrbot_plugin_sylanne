"""Fixed administrator-owned systemd supervisor for lifecycle/maintenance steps.

No browser path, executable, unit or argument vector is accepted. These methods
are internal to the authenticated lifecycle service, not generic RPC methods.
Process observations prove process state only; they never fabricate Graph,
backup, native-load, model-accounting or version-activation receipts.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import os
import re
import stat
import subprocess
import sys

from .contract import AuthorityUnavailable
from ..runtime.lifecycle_operations_v1 import digest


@dataclass(frozen=True, slots=True)
class D12SystemdSupervisorConfigV1:
    unit_name: str
    systemctl_path: str
    unit_fragment_path: str
    unit_fragment_sha256: str
    control_group: str
    timeout_seconds: int = 60

    def __post_init__(self):
        if re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", self.unit_name) is None:
            raise ValueError("one fixed installed systemd unit required")
        if (not Path(self.systemctl_path).is_absolute() or not Path(self.unit_fragment_path).is_absolute()
                or re.fullmatch(r"[0-9a-f]{64}", self.unit_fragment_sha256) is None
                or not self.control_group.startswith("/") or ".." in Path(self.control_group).parts
                or type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300):
            raise ValueError("fixed supervisor executable, unit digest, cgroup and bounded timeout required")


@dataclass(frozen=True, slots=True)
class D12SupervisorObservationV1:
    unit_name: str
    load_state: str
    active_state: str
    sub_state: str
    main_pid: int
    invocation_id: str
    control_group: str
    process_ids: tuple[int, ...]
    unit_fragment_sha256: str
    observation_digest: str

    @property
    def stopped_and_drained(self):
        return (self.active_state in {"inactive", "failed"} and self.main_pid == 0
                and not self.process_ids)


class InstalledD12SystemdSupervisorV1:
    def __init__(self, *, config: D12SystemdSupervisorConfigV1):
        if type(config) is not D12SystemdSupervisorConfigV1 or not sys.platform.startswith("linux"):
            raise AuthorityUnavailable("installed Linux systemd supervisor required")
        self.config = config
        self._verify_installation()

    @staticmethod
    def _root_owned_regular(path):
        path = Path(path)
        for item in (path, *path.parents):
            st = item.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise AuthorityUnavailable("supervisor installation path is not administrator-owned")
        if not path.is_file():
            raise AuthorityUnavailable("supervisor installation file is absent")
        return path

    def _verify_installation(self):
        binary = self._root_owned_regular(self.config.systemctl_path)
        fragment = self._root_owned_regular(self.config.unit_fragment_path)
        if not os.access(binary, os.X_OK) or sha256(fragment.read_bytes()).hexdigest() != self.config.unit_fragment_sha256:
            raise AuthorityUnavailable("supervisor installed executable or unit bytes changed")

    def _run(self, arguments):
        self._verify_installation()
        return subprocess.run([self.config.systemctl_path, *arguments],
            shell=False, check=False, capture_output=True, text=True,
            timeout=self.config.timeout_seconds,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0"})

    def read_current_host_state_v1(self):
        response = self._run(["show", self.config.unit_name, "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,MainPID,InvocationID,ControlGroup,FragmentPath"])
        if response.returncode != 0:
            raise AuthorityUnavailable("systemd current installed unit observation failed")
        fields = {}
        for line in response.stdout.splitlines():
            name, separator, value = line.partition("=")
            if not separator or name in fields:
                raise AuthorityUnavailable("systemd current unit observation is malformed")
            fields[name] = value
        if (set(fields) != {"Id", "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID", "ControlGroup", "FragmentPath"}
                or fields["Id"] != self.config.unit_name or fields["LoadState"] != "loaded"
                or fields["FragmentPath"] != self.config.unit_fragment_path
                or fields["ControlGroup"] not in {"", self.config.control_group}
                or not fields["MainPID"].isdigit()
                or fields["InvocationID"] and re.fullmatch(r"[0-9a-f]{32}", fields["InvocationID"]) is None):
            raise AuthorityUnavailable("systemd observation differs from installed unit identity")
        cgroup = Path("/sys/fs/cgroup") / self.config.control_group.lstrip("/")
        # The administrator pins the unit's cgroup. All descendant process lists
        # are read so a zero MainPID cannot hide a surviving worker process.
        pids = set()
        if cgroup.exists():
            for process_file in cgroup.rglob("cgroup.procs"):
                if process_file.is_symlink():
                    raise AuthorityUnavailable("installed cgroup process list is a symlink")
                pids.update(int(line) for line in process_file.read_text().splitlines())
        material = dict(unit_name=fields["Id"], load_state=fields["LoadState"],
            active_state=fields["ActiveState"], sub_state=fields["SubState"],
            main_pid=int(fields["MainPID"]), invocation_id=fields["InvocationID"],
            control_group=self.config.control_group, process_ids=tuple(sorted(pids)),
            unit_fragment_sha256=self.config.unit_fragment_sha256)
        return D12SupervisorObservationV1(**material, observation_digest=digest(material))

    def stop_original_host_v1(self, *, expected_invocation_id):
        before = self.read_current_host_state_v1()
        if before.stopped_and_drained:
            return before
        if before.invocation_id != expected_invocation_id:
            raise AuthorityUnavailable("host incarnation changed before original quiesce")
        try:
            response = self._run(["stop", self.config.unit_name])
        except subprocess.TimeoutExpired:
            # Recover this original stop from current OS state. Never report
            # success from timeout or launch another action with a new identity.
            after = self.read_current_host_state_v1()
            if after.stopped_and_drained:
                return after
            raise AuthorityUnavailable("original host stop outcome is unresolved") from None
        after = self.read_current_host_state_v1()
        if response.returncode != 0 or not after.stopped_and_drained:
            raise AuthorityUnavailable("installed host has not actually stopped and drained")
        return after

    def start_stopped_host_v1(self, *, expected_prior_invocation_id):
        before = self.read_current_host_state_v1()
        if not before.stopped_and_drained:
            raise AuthorityUnavailable("original candidate start requires a stopped/drained host")
        if before.invocation_id not in {"", expected_prior_invocation_id}:
            raise AuthorityUnavailable("stopped host incarnation differs from maintenance intent")
        try:
            response = self._run(["start", self.config.unit_name])
        except subprocess.TimeoutExpired:
            raise AuthorityUnavailable("original host start outcome is unresolved; inspect this same stage") from None
        after = self.read_current_host_state_v1()
        if (response.returncode != 0 or after.active_state != "active" or after.main_pid < 1
                or not after.invocation_id or after.invocation_id == expected_prior_invocation_id
                or after.main_pid not in after.process_ids):
            raise AuthorityUnavailable("candidate host has not actually started in a new incarnation")
        return after


__all__ = ("D12SystemdSupervisorConfigV1", "D12SupervisorObservationV1", "InstalledD12SystemdSupervisorV1")
