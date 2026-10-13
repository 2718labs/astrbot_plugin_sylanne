"""Installed PID1 process owner and its closed, root-only Authority adapter.

The live registry is owned by the launcher that creates the actual children.
Neither a spec nor a serialized observation can register a process.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import ctypes
import hashlib
import json
import logging
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import traceback
from uuid import uuid4
from weakref import WeakSet,WeakKeyDictionary
import threading

from .contract import AuthorityUnavailable
from .c09_process_identity_v1 import read_process_identity_v1
from .linux_installation_security_v1 import read_installed_bytes_v1, read_installed_json_v1
from ..runtime.lifecycle_operations_v1 import digest

KIND = "root_supervised_process_v1"


def _supervisor_stage_event_v1(stage, event, *, sequence=None, role=None, cohort_digest=None,
        started_ns=None, peer_pid=None, exception_type=None):
    observed = time.monotonic_ns()
    metadata = {"stage": stage, "event": event, "sequence": sequence,
        "role": role, "cohort_digest": cohort_digest, "process_id": os.getpid(), "monotonic_ns": observed,
        "wall_time_ns": time.time_ns()}
    if started_ns is not None:
        metadata["elapsed_ns"] = observed - started_ns
    if peer_pid is not None:
        metadata["peer_pid"] = peer_pid
    if exception_type is not None:
        metadata["exception_type"] = exception_type
    logging.getLogger(__name__).warning("Sylanne D12 root supervisor stage metadata: " +
        json.dumps(metadata, separators=(",", ":")))
    return observed


@contextmanager
def _supervisor_diagnostic_stage_v1(stage, *, sequence=None, role=None, cohort_digest=None):
    started = _supervisor_stage_event_v1(stage, "start", sequence=sequence,
        role=role, cohort_digest=cohort_digest)
    try:
        yield
    except BaseException as exc:
        _supervisor_stage_event_v1(stage, "error", sequence=sequence, role=role,
            cohort_digest=cohort_digest, started_ns=started, exception_type=type(exc).__name__)
        raise
    else:
        _supervisor_stage_event_v1(stage, "end", sequence=sequence, role=role,
            cohort_digest=cohort_digest, started_ns=started)


@dataclass(frozen=True, slots=True)
class InstalledProcessSupervisorSpecV2:
    schema: str
    provider_kind: str
    supervisor_id: str
    installation_id: str
    authority_id: str
    profile_id: str
    namespace_cohort: tuple[str, ...]
    service_role: str
    installed_spec_path: str
    launcher_code_ref: str
    launcher_build_digest: str
    fixed_executable_path: str
    executable_sha256: str
    fixed_entry_ref: str
    entry_sha256: str
    fixed_argv: tuple[str, ...]
    fixed_cwd: str
    finite_environment_policy: dict[str, str]
    expected_uid: int
    expected_gid: int
    supplementary_group_policy: str
    bootstrap_package_ref: str
    selection_control_directory: str
    control_socket_path: str
    protected_state_directory: str
    maximum_processes: int
    start_timeout: int
    drain_timeout: int

    def __post_init__(self):
        object.__setattr__(self, "namespace_cohort", tuple(self.namespace_cohort))
        object.__setattr__(self, "fixed_argv", tuple(self.fixed_argv))
        if (self.schema != "sylanne3.installed-process-supervisor.v2" or self.provider_kind != KIND
                or self.selection_control_directory != "/etc/sylanne/maintenance"
                or not self.bootstrap_package_ref.startswith("bootstrap:")
                or self.service_role not in {"host", "authority"}
                or len(self.namespace_cohort) != 1 or not self.supervisor_id
                or type(self.expected_uid) is not int or type(self.expected_gid) is not int
                or self.service_role == "authority" and self.expected_uid != 0
                or self.service_role == "host" and (self.expected_uid < 1 or self.expected_gid < 1)
                or self.service_role == "authority" and self.expected_gid != 0
                or self.supplementary_group_policy != "drop_all"
                or not 2 <= self.maximum_processes <= 256
                or not 1 <= self.start_timeout <= 60 or not 1 <= self.drain_timeout <= 60
                or any(not Path(value).is_absolute() for value in (
                    self.installed_spec_path, self.launcher_code_ref, self.fixed_executable_path,
                    self.fixed_entry_ref, self.fixed_cwd, self.control_socket_path, self.protected_state_directory))
                or not self.fixed_argv or self.fixed_argv[0] != self.fixed_executable_path
                or self.fixed_entry_ref not in self.fixed_argv
                or type(self.finite_environment_policy) is not dict
                or len(self.finite_environment_policy) > 16
                or any(type(k) is not str or type(v) is not str or "\0" in k + v
                       for k, v in self.finite_environment_policy.items())):
            raise AuthorityUnavailable("closed installed process supervisor spec differs")
        for pin in (self.launcher_build_digest, self.executable_sha256, self.entry_sha256,
                    self.bootstrap_package_ref.removeprefix("bootstrap:")):
            if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
                raise AuthorityUnavailable("installed process code/cohort digest differs")

    @property
    def spec_digest(self):
        return digest(asdict(self))


def load_process_supervisor_spec_v1(path):
    raw = read_installed_json_v1(path, limit=32768)
    if type(raw) is not dict or set(raw) != set(InstalledProcessSupervisorSpecV2.__dataclass_fields__):
        raise AuthorityUnavailable("closed installed supervisor file required")
    spec = InstalledProcessSupervisorSpecV2(**raw)
    if Path(spec.installed_spec_path) != Path(path):
        raise AuthorityUnavailable("supervisor spec is not at its installed path")
    return spec


def verify_process_supervisor_spec_v1(spec):
    if type(spec) is not InstalledProcessSupervisorSpecV2 or load_process_supervisor_spec_v1(spec.installed_spec_path) != spec:
        raise AuthorityUnavailable("process spec differs from protected installation")
    for path, pin in ((spec.launcher_code_ref, spec.launcher_build_digest),
                      (spec.fixed_executable_path, spec.executable_sha256),
                      (spec.fixed_entry_ref, spec.entry_sha256)):
        if hashlib.sha256(read_installed_bytes_v1(path, limit=64 * 1024 * 1024)).hexdigest() != pin:
            raise AuthorityUnavailable("installed supervised code bytes changed")
    for directory in (Path(spec.fixed_cwd), Path(spec.protected_state_directory),
                      Path(spec.control_socket_path).parent):
        for component in (directory, *directory.parents):
            info = component.lstat()
            if not component.is_dir() or component.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise AuthorityUnavailable("supervisor directory is not root protected")


@dataclass(frozen=True, slots=True)
class D12SupervisorObservationV2:
    provider_kind: str
    supervisor_id: str
    spec_digest: str
    service_role: str
    installed_code_digest: str
    selection_revision: int
    selected_cohort_digest: str
    selected_release_ref: str
    selected_manifest_digest: str
    launch_entry_ref: str
    launch_entry_sha256: str
    launch_argv: tuple[str, ...]
    expected_final_entry: str
    expected_final_entry_sha256: str
    expected_final_argv: tuple[str, ...]
    invocation_id: str
    main_process_original: dict | None
    main_pid: int
    main_process_details: dict | None
    launcher_process_original: dict
    pid_namespace_identity: str
    mount_namespace_identity: str
    process_originals: tuple[dict, ...]
    process_ids: tuple[int, ...]
    state: str
    observation_sequence: int
    observation_digest: str

    @property
    def stopped_and_drained(self):
        return self.state in {"stopped", "failed"} and self.main_pid == 0 and not self.process_ids

    @property
    def active_state(self):
        # Logical lifecycle state; no systemd fields are serialized by V2.
        return {"active": "active", "stopped": "inactive", "failed": "failed"}.get(self.state, self.state)


def decode_process_supervisor_observation_v2(raw):
    if type(raw) is not dict or set(raw) != set(D12SupervisorObservationV2.__dataclass_fields__):
        raise AuthorityUnavailable("closed process supervisor observation required")
    value = dict(raw)
    value["process_originals"] = tuple(value["process_originals"])
    value["process_ids"] = tuple(value["process_ids"])
    value["launch_argv"] = tuple(value["launch_argv"])
    value["expected_final_argv"] = tuple(value["expected_final_argv"])
    observed = D12SupervisorObservationV2(**value)
    material = asdict(observed)
    material.pop("observation_digest")
    if (observed.provider_kind != KIND or observed.service_role not in {"host", "authority"}
            or observed.state not in {"starting", "active", "draining", "stopped", "failed", "unknown"}
            or type(observed.main_pid) is not int or observed.main_pid < 0
            or type(observed.observation_sequence) is not int or observed.observation_sequence < 1
            or type(observed.selection_revision) is not int or observed.selection_revision < 0
            or observed.observation_digest != digest(material)
            or any(type(pid) is not int or pid < 1 for pid in observed.process_ids)
            or observed.process_ids != tuple(sorted(set(observed.process_ids)))
            or tuple(p["pid"] for p in observed.process_originals) != observed.process_ids
            or any(set(p) != {"pid", "platform", "birth"} or p["platform"] != "linux"
                   or not p["birth"] or p["pid"] < 1 for p in observed.process_originals)
            or observed.main_pid and (observed.main_process_original is None
                or observed.main_process_original["pid"] != observed.main_pid
                or observed.main_pid not in observed.process_ids or observed.main_process_details is None)
            or not observed.main_pid and (observed.main_process_original is not None or observed.main_process_details is not None)):
        raise AuthorityUnavailable("process observation identity/commitment differs")
    if (observed.state == "active" and not observed.main_pid
            or observed.state in {"stopped", "failed"} and (observed.main_pid or observed.process_ids)):
        raise AuthorityUnavailable("process observation state contradicts its actual inventory")
    return observed


def _read_selected_invocation(spec, *, diagnostic_sequence=None):
    """Resolve the existing protected registry, then derive the exact final exec.

    Static spec -> policy/cohort -> selection -> this live binding is acyclic.
    The fields measured here are never fed back into static spec files.
    """
    from .d12_package_files_v2 import InstalledPackageSelectionFilesV2, _digest
    files = InstalledPackageSelectionFilesV2(control_directory=spec.selection_control_directory)
    with _supervisor_diagnostic_stage_v1("selected_cohort_initial", sequence=diagnostic_sequence,
            role=spec.service_role):
        selected, cohort, configuration = files.read_selected_configuration_cohort_v2()
    from .d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
    with _supervisor_diagnostic_stage_v1("fixed_supervisor_policy", sequence=diagnostic_sequence,
            role=spec.service_role, cohort_digest=selected.cohort_digest):
        policy, host_spec, authority_spec = read_fixed_supervisor_policy_v2(files)
    if spec != (host_spec if spec.service_role == "host" else authority_spec):
        raise AuthorityUnavailable("live selection has another installed fixed supervisor")
    if (selected.installation_id != spec.installation_id
            or policy["authority_id"] != spec.authority_id or policy["profile_id"] != spec.profile_id
            or policy["namespace_cohort"] != list(spec.namespace_cohort)
            or _digest(policy) != cohort.supervisor_policy_digest
            or spec.bootstrap_package_ref != "bootstrap:" + policy["bootstrap_manifest_sha256"]
            or policy[spec.service_role + "_supervisor"] != json.loads(json.dumps(asdict(spec)))):
        raise AuthorityUnavailable("actual selected registry differs from fixed installed process spec")
    if (configuration["deployment"]["schema"] != "sylanne3.authority.linux-deployment.v2"
            or configuration["deployment"]["host_supervisor_provider"]["installation_id"] != spec.installation_id):
        raise AuthorityUnavailable("selected deployment has no exact installed process provider")
    if spec.service_role == "authority":
        final_entry = Path(cohort.package.package_root) / "scripts" / "alpha1" / "authority_linux_service.py"
        deployment = next(item.path for item in cohort.files if item.role == "deployment")
        from scripts.alpha1.linux_startup_shims_v2 import selected_authority_command_v2
        final_argv = selected_authority_command_v2(executable=spec.fixed_executable_path,
            package_root=cohort.package.package_root, deployment_path=deployment,
            selection_revision=selected.revision, cohort_digest=selected.cohort_digest)
    else:
        final_entry = Path(spec.fixed_entry_ref)
        final_argv = spec.fixed_argv
    final_sha = hashlib.sha256(read_installed_bytes_v1(final_entry, limit=4 * 1024 * 1024)).hexdigest()
    if spec.service_role == "authority":
        # This verifies every selected package member, including the final entry.
        with _supervisor_diagnostic_stage_v1("authority_registered_package", sequence=diagnostic_sequence,
                role=spec.service_role, cohort_digest=selected.cohort_digest):
            files.verify_registered_package_v2(cohort.package)
    elif final_sha != spec.entry_sha256:
        raise AuthorityUnavailable("fixed Host SDK entry code changed")
    with _supervisor_diagnostic_stage_v1("selected_cohort_final", sequence=diagnostic_sequence,
            role=spec.service_role, cohort_digest=selected.cohort_digest):
        after, _, _ = files.read_selected_configuration_cohort_v2()
    if after != selected:
        raise AuthorityUnavailable("selected cohort changed while deriving the exact final exec")
    return dict(selection_revision=selected.revision, selected_cohort_digest=selected.cohort_digest,
                selected_release_ref=selected.release_ref, selected_manifest_digest=selected.manifest_sha256,
                launch_entry_ref=spec.fixed_entry_ref, launch_entry_sha256=spec.entry_sha256,
                launch_argv=spec.fixed_argv, expected_final_entry=str(final_entry),
                expected_final_entry_sha256=final_sha, expected_final_argv=final_argv)


def _namespace_identity(pid, name):
    return os.readlink(f"/proc/{pid}/ns/{name}")


def _inventory_birth(pid):
    """Birth for physically present role entries, including unreaped zombies.

    This is inventory, not the live C09 admission original. A zombie must remain
    in the set until PID1 has actually reaped it.
    """
    tail = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "platform": "linux", "birth":
            Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + tail[19]}


def _process_details(pid):
    root = Path("/proc") / str(pid)
    rows = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines() if ":" in line)
    exe = os.readlink(root / "exe")
    return {"uids": tuple(int(v) for v in rows["Uid"].split()),
            "gids": tuple(int(v) for v in rows["Gid"].split()),
            "groups": tuple(int(v) for v in rows["Groups"].split()),
            "cap_effective": rows["CapEff"].strip(), "cap_permitted": rows["CapPrm"].strip(),
            "no_new_privs": rows["NoNewPrivs"].strip(), "executable": exe,
            "argv": tuple(part.decode() for part in (root / "cmdline").read_bytes().split(b"\0") if part),
            "executable_sha256": hashlib.sha256((root / "exe").read_bytes()).hexdigest()}


def _host_credentials(spec):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "no_new_privs unavailable")
    last = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    for capability in range(last + 1):
        if libc.prctl(24, capability, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "capability bounding drop failed")
    os.setgroups([])
    os.setresgid(spec.expected_gid, spec.expected_gid, spec.expected_gid)
    os.setresuid(spec.expected_uid, spec.expected_uid, spec.expected_uid)


_ROOT_GENESIS_HOLDS_V3 = WeakSet()
_ROOT_GENESIS_HOLD_ISSUER_V3 = object()


class RootPeerRegistryGenesisHoldV3:
    """Actual root channel keeps installed Host starts excluded until release."""
    def __init__(self, issuer, adapter, channel, response, launcher, authority):
        if issuer is not _ROOT_GENESIS_HOLD_ISSUER_V3:
            raise AuthorityUnavailable("actual installed Root genesis channel issuer required")
        self.adapter, self.channel = adapter, channel
        self.original, self.launcher_original, self.authority_original = response, launcher, authority
        self.owner_thread, self.released = threading.get_ident(), False
        self.observation=decode_process_supervisor_observation_v2(response['observation'])
        if (response['status']!='registry_genesis_held' or self.observation.service_role!='host'
                or self.observation.spec_digest!=adapter.config.spec_digest
                or not self.observation.stopped_and_drained
                or response['root_process_original']!=launcher
                or response['authority_process_original']!=authority
                or not response['root_channel_nonce']):
            raise AuthorityUnavailable("actual complete Root Host genesis census differs")
        _ROOT_GENESIS_HOLDS_V3.add(self)

    def require_current(self):
        if (self not in _ROOT_GENESIS_HOLDS_V3 or self.released
                or self.owner_thread!=threading.get_ident() or self.channel.fileno()<0
                or read_process_identity_v1(1)!=self.launcher_original
                or read_process_identity_v1(os.getpid())!=self.authority_original
                or select.select([self.channel],[],[],0)[0]):
            raise AuthorityUnavailable("continuous installed Root genesis channel exclusion ended")

    def close(self):
        if not self.released:
            self.released=True
            try:
                self.channel.sendall(json.dumps({'root_channel_nonce':self.original['root_channel_nonce'],
                    'action':'release_registry_genesis'},separators=(',',':')).encode()+b'\n')
            finally:
                self.channel.close()


_ROOT_PEER_BASELINES_V3=WeakSet()
_ROOT_PEER_OBSERVATIONS_V3=WeakSet()
_ROOT_PEER_OBSERVATION_BINDINGS_V3=WeakKeyDictionary()
_ROOT_PEER_START_ISSUER_V3=object()
_ROOT_PEER_CHANNEL_READERS_V3=WeakKeyDictionary()


def _read_peer_start_packet_v3(channel,*,limit=262144):
    reader=_ROOT_PEER_CHANNEL_READERS_V3.get(channel)
    if reader is None:
        reader=channel.makefile('rb')
        _ROOT_PEER_CHANNEL_READERS_V3[channel]=reader
    raw=reader.readline(limit+1)
    if len(raw)>limit or not raw.endswith(b'\n'):
        raise AuthorityUnavailable('actual bounded Root peer-start channel packet required')
    return json.loads(raw)


def _close_peer_start_channel_v3(channel):
    reader=_ROOT_PEER_CHANNEL_READERS_V3.pop(channel,None)
    try:
        if reader is not None:reader.close()
    finally:channel.close()


@contextmanager
def _peer_start_channel_scope_v3(channel):
    try:yield channel
    finally:_close_peer_start_channel_v3(channel)


class RootPeerStartBaselineV3:
    def __init__(self,issuer,*,supervisor,channel,response,peer,root,authority):
        if issuer is not _ROOT_PEER_START_ISSUER_V3:
            raise AuthorityUnavailable('actual continuous Root peer baseline issuer required')
        self.supervisor,self.channel,self.peer=supervisor,channel,peer
        self.gate,self.control=supervisor._peer_registry_gate_v3,supervisor._peer_registry_control_v3
        self.observation=decode_process_supervisor_observation_v2(response['observation'])
        self.channel_nonce=response['root_channel_nonce']
        self.root_process_original,self.authority_process_original=root,authority
        self.owner_thread,self.closed,self.start_sent=threading.get_ident(),False,False
        if (response['status']!='peer_start_held' or response['root_process_original']!=root
                or response['authority_process_original']!=authority
                or self.observation.launcher_process_original!=root
                or self.observation.spec_digest!=supervisor.config.spec_digest
                or self.observation.service_role!='host' or not self.channel_nonce):
            raise AuthorityUnavailable('actual Root peer baseline channel differs')
        _ROOT_PEER_BASELINES_V3.add(self)
    def require_current(self,*,control,gate,meter):
        if (self not in _ROOT_PEER_BASELINES_V3 or self.control is not control or self.gate is not gate
                or self.closed or self.owner_thread!=threading.get_ident() or self.channel.fileno()<0
                or self.supervisor._peer_registry_gate_v3 is not gate
                or gate._pending_start_supervisor_v3 is not self.supervisor
                or read_process_identity_v1(1)!=self.root_process_original
                or read_process_identity_v1(os.getpid())!=self.authority_process_original
                or select.select([self.channel],[],[],0)[0]):
            raise AuthorityUnavailable('continuous actual Root peer baseline exclusion ended')
        return self
    def start_v3(self,*,pending,activation,host_start):
        if self.start_sent:raise AuthorityUnavailable('the original Root pending start was already dispatched')
        self.require_current(control=self.control,gate=self.gate,meter=None)
        self.start_sent=True
        self.channel.sendall(json.dumps(dict(action='start_peer',root_channel_nonce=self.channel_nonce,
            pending_start_original=pending,registry_activation=activation,registry_host_start=host_start),
            separators=(',',':')).encode()+b'\n')
        return self.observe_response_v3(pending)
    def observe_response_v3(self,pending):
        value=_read_peer_start_packet_v3(self.channel)
        if (value.get('status')!='peer_start_observed' or value.get('root_channel_nonce')!=self.channel_nonce
                or value.get('pending_start_digest')!=pending['pending_start_digest']):
            raise AuthorityUnavailable('actual original Root pending start observation unavailable')
        observed=decode_process_supervisor_observation_v2(value['observation'])
        if (observed.launcher_process_original!=self.root_process_original
                or observed.spec_digest!=self.supervisor.config.spec_digest or observed.service_role!='host'):
            raise AuthorityUnavailable('actual Root pending observation belongs to another installed role')
        return observed
    def close(self,completion=None):
        if self.closed:return
        try:
            self.channel.sendall(json.dumps(dict(action='release_peer_start_hold',root_channel_nonce=self.channel_nonce,
                completion_original=completion),separators=(',',':')).encode()+b'\n')
            if completion is not None:
                value=_read_peer_start_packet_v3(self.channel)
                if value!=dict(status='peer_start_released',root_channel_nonce=self.channel_nonce):
                    raise AuthorityUnavailable('actual Root pending completion release ACK differs')
        finally:
            self.closed=True
            _close_peer_start_channel_v3(self.channel)


class RootPeerStartCoverageHoldV3(RootPeerStartBaselineV3):
    def resolve_pending_v3(self,pending):
        self.require_current(control=self.control,gate=self.gate,meter=None)
        self.channel.sendall(json.dumps(dict(action='resolve_pending_peer',root_channel_nonce=self.channel_nonce,
            pending_start_original=pending),separators=(',',':')).encode()+b'\n')
        observed=self.observe_response_v3(pending)
        if not observed.stopped_and_drained:
            raise AuthorityUnavailable('actual cold pending Host cohort has not fully retired')
        return RootObservedPeerStartV3(_ROOT_PEER_START_ISSUER_V3,baseline=self,pending=pending,
            observation=observed,admission=None)
    def ack_old_root_pending_v3(self,pending,physical,completion):
        self.require_current(control=self.control,gate=self.gate,meter=None)
        self.channel.sendall(json.dumps(dict(action='ack_old_root_pending',root_channel_nonce=self.channel_nonce,
            pending_start_original=pending,retirement_original=physical,completion_original=completion),
            separators=(',',':')).encode()+b'\n')
        value=_read_peer_start_packet_v3(self.channel)
        if value!=dict(status='pending_peer_completed',root_channel_nonce=self.channel_nonce):
            raise AuthorityUnavailable('actual Root old-cohort retirement/completion ACK differs')

    def ack_pending_v3(self,completion):
        self.channel.sendall(json.dumps(dict(action='complete_pending_peer',root_channel_nonce=self.channel_nonce,
            completion_original=completion),separators=(',',':')).encode()+b'\n')
        value=_read_peer_start_packet_v3(self.channel)
        if value!=dict(status='pending_peer_completed',root_channel_nonce=self.channel_nonce):
            raise AuthorityUnavailable('actual Root pending completion ACK differs')
    def close(self,completion=None):
        if self.closed:return
        try:
            if completion is not None:
                self.channel.sendall(json.dumps(dict(action='release_peer_start_coverage',root_channel_nonce=self.channel_nonce,
                    coverage_original=completion),separators=(',',':')).encode()+b'\n')
                value=_read_peer_start_packet_v3(self.channel)
                if value!=dict(status='peer_start_coverage_released',root_channel_nonce=self.channel_nonce):
                    raise AuthorityUnavailable('actual Root pending EOF release ACK differs')
        finally:
            self.closed=True;_close_peer_start_channel_v3(self.channel)


class RootObservedPeerStartV3:
    def __init__(self,issuer,*,baseline,pending,observation,admission):
        if issuer is not _ROOT_PEER_START_ISSUER_V3 or baseline not in _ROOT_PEER_BASELINES_V3:
            raise AuthorityUnavailable('actual Root pending-start observation issuer required')
        self.baseline=baseline
        self.supervisor,self.gate,self.control=baseline.supervisor,baseline.gate,baseline.control
        self.pending_original,self.observation,self.admission_original=pending,observation,admission
        _ROOT_PEER_OBSERVATIONS_V3.add(self)
        _ROOT_PEER_OBSERVATION_BINDINGS_V3[self]=(baseline,pending['pending_start_digest'],
            observation.observation_digest,None if admission is None else admission['admission_digest'])
    def require_current(self,*,control,gate,meter):
        if self not in _ROOT_PEER_OBSERVATIONS_V3 or self.control is not control or self.gate is not gate:
            raise AuthorityUnavailable('actual Root pending-start completion scope changed')
        binding=_ROOT_PEER_OBSERVATION_BINDINGS_V3[self]
        if (self.baseline is not binding[0] or self.pending_original['pending_start_digest']!=binding[1]
                or self.observation.observation_digest!=binding[2]
                or (None if self.admission_original is None else self.admission_original['admission_digest'])!=binding[3]):
            raise AuthorityUnavailable('actual issued Root pending observation original changed')
        self.baseline.require_current(control=control,gate=gate,meter=meter)
        if self.observation.stopped_and_drained:
            if self.admission_original is not None:
                raise AuthorityUnavailable('retired Root census cannot claim a live admission')
        elif (self.admission_original is None or self.observation.main_process_original is None
                or read_process_identity_v1(self.observation.main_pid)!=self.observation.main_process_original
                or self.admission_original['process_original']!=self.observation.main_process_original):
            raise AuthorityUnavailable('actual born Host must have its matching durable admission')
        return self


class RootProcessLauncherV1:
    """PID1 owns fixed live children and kills the entire measured Host UID set."""
    def __init__(self, *, host_spec_path, authority_spec_path):
        if (os.getpid() != 1 or os.geteuid() != 0 or not hasattr(os, "pidfd_open")
                or not hasattr(signal, "pidfd_send_signal")
                or os.readlink("/proc/self") != "1"
                or read_process_identity_v1(1) != read_process_identity_v1(os.getpid())):
            raise AuthorityUnavailable("private procfs PID1 root launcher/pidfd primitives required")
        self.specs = {spec.service_role: spec for spec in (
            load_process_supervisor_spec_v1(host_spec_path), load_process_supervisor_spec_v1(authority_spec_path))}
        if set(self.specs) != {"host", "authority"}:
            raise AuthorityUnavailable("exactly two installed service roles required")
        host, authority = self.specs["host"], self.specs["authority"]
        shared = ("installation_id", "authority_id", "profile_id", "namespace_cohort", "launcher_code_ref",
                  "launcher_build_digest", "control_socket_path", "protected_state_directory")
        if any(getattr(host, name) != getattr(authority, name) for name in shared) or host.supervisor_id == authority.supervisor_id:
            raise AuthorityUnavailable("registered process supervisor installation differs")
        for spec in self.specs.values():
            verify_process_supervisor_spec_v1(spec)
        actual_entry = str(Path(sys.argv[0]).resolve())
        if actual_entry != host.launcher_code_ref:
            raise AuthorityUnavailable("PID1 is not the pinned installed launcher entry")
        self.launcher_original = read_process_identity_v1(1)
        self.pid_namespace = _namespace_identity(1, "pid")
        self.mount_namespace = _namespace_identity(1, "mnt")
        self.registry = {}
        self.sequence = 0
        self._control_diagnostic_sequence = 0
        self._active_control_diagnostic_sequence = None
        self.retiring = False
        self.listener = None
        import fcntl
        lease_path = Path(host.protected_state_directory) / "launcher.lock"
        self.lease_fd = os.open(lease_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.lease_fd)
        if info.st_uid != 0 or info.st_mode & 0o077:
            os.close(self.lease_fd)
            raise AuthorityUnavailable("launcher lifetime lock is not root private")
        try:
            fcntl.flock(self.lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lease_fd)
            raise AuthorityUnavailable("another launcher still owns this installed lifetime") from None

    def _reap(self):
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            for record in self.registry.values():
                if record["process"].pid == pid:
                    record["process"].returncode = os.waitstatus_to_exitcode(status)

    def _inventory(self, role):
        if (os.readlink("/proc/self") != "1" or _namespace_identity(1, "pid") != self.pid_namespace
                or _namespace_identity(1, "mnt") != self.mount_namespace):
            raise AuthorityUnavailable("supervised private process universe changed")
        self._reap()
        spec = self.specs[role]
        originals = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal() or entry.name == "1":
                continue
            try:
                rows = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines() if ":" in line)
                uids = tuple(int(v) for v in rows["Uid"].split())
                if uids[0] != spec.expected_uid:
                    continue
                if uids != (spec.expected_uid,) * 4:
                    raise AuthorityUnavailable("role process changed its saved OS principal")
                originals.append(_inventory_birth(int(entry.name)))
            except FileNotFoundError:
                continue
        if len(originals) > spec.maximum_processes:
            raise AuthorityUnavailable("supervised process inventory exceeds installed bound")
        return tuple(sorted(originals, key=lambda p: p["pid"]))

    @staticmethod
    def _pin(original):
        fd = os.pidfd_open(original["pid"], 0)
        try:
            if _inventory_birth(original["pid"]) != original:
                raise AuthorityUnavailable("process incarnation changed during handle acquisition")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _observe(self, role):
        with _supervisor_diagnostic_stage_v1("process_observe",
                sequence=self._active_control_diagnostic_sequence, role=role):
            spec = self.specs[role]
            verify_process_supervisor_spec_v1(spec)
            originals = self._inventory(role)
            record = self.registry.get(role)
            main, details, pid = None, None, 0
            state = "stopped"
            invocation = record["invocation"] if record else ""
            selected_invocation = record["selected"] if record else _read_selected_invocation(spec, diagnostic_sequence=self._active_control_diagnostic_sequence)
            if record and not select.select([record["pidfd"]], [], [], 0)[0]:
                if _read_selected_invocation(spec, diagnostic_sequence=self._active_control_diagnostic_sequence) != selected_invocation:
                    raise AuthorityUnavailable("current selected cohort changed under a live invocation")
                main = read_process_identity_v1(record["process"].pid)
                if main != record["original"]:
                    if select.select([record["pidfd"]], [], [], 0)[0]:
                        return self._observe(role)
                    raise AuthorityUnavailable("registered main process birth changed")
                details = _process_details(main["pid"])
                if (details["uids"] != (spec.expected_uid,) * 4 or details["gids"] != (spec.expected_gid,) * 4
                        or details["groups"] or details["executable"] != spec.fixed_executable_path
                        or details["executable_sha256"] != spec.executable_sha256
                        or role == "host" and (int(details["cap_effective"], 16) or int(details["cap_permitted"], 16)
                                                 or details["no_new_privs"] != "1")):
                    raise AuthorityUnavailable("registered main differs from its fixed code/OS invocation")
                pid = main["pid"]
                if details["argv"] == selected_invocation["expected_final_argv"]:
                    state = "active"
                elif role == "authority" and details["argv"] == spec.fixed_argv:
                    # The verified bootstrap is genuinely executing, but has not
                    # yet exec'd the exact selected entry. It has no admission.
                    state = "starting"
                else:
                    raise AuthorityUnavailable("registered main executed an unregistered argument vector")
            elif originals:
                state = "draining"
            elif record and record["process"].returncode not in {None, 0}:
                state = "failed"
            self.sequence += 1
            material = dict(provider_kind=KIND, supervisor_id=spec.supervisor_id, spec_digest=spec.spec_digest,
                service_role=role, installed_code_digest=digest((spec.launcher_build_digest, spec.executable_sha256,
                    spec.entry_sha256, selected_invocation["expected_final_entry_sha256"], selected_invocation["selected_manifest_digest"])),
                **selected_invocation,
                invocation_id=invocation, main_process_original=main, main_pid=pid, main_process_details=details,
                launcher_process_original=self.launcher_original, pid_namespace_identity=self.pid_namespace,
                mount_namespace_identity=self.mount_namespace, process_originals=originals,
                process_ids=tuple(p["pid"] for p in originals), state=state, observation_sequence=self.sequence)
            return D12SupervisorObservationV2(**material, observation_digest=digest(material))

    def _require_peer_registry_host_start_v3(self, request, authority):
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        from .c09_writer_peer_originals_v3 import verify_writer_peer_registry_host_start_original_v3
        files=InstalledPackageSelectionFilesV2(control_directory=self.specs['authority'].selection_control_directory)
        selected,cohort,configuration=files.read_selected_configuration_cohort_v2()
        spec=self.specs['host']
        c09=configuration['assets'].get('c09_storage_v1')
        if (type(c09) is not dict or selected.installation_id!=spec.installation_id
                or c09['installation_id']!=spec.installation_id or c09['authority_id']!=spec.authority_id
                or authority.selected_cohort_digest!=selected.cohort_digest):
            raise AuthorityUnavailable('actual selected production Host registry scope differs')
        key=read_installed_bytes_v1(c09['key_path'],private=True,allowed_gid=0,limit=4096)
        verify_writer_peer_registry_host_start_original_v3(request['registry_host_start'],
            activation_original=request['registry_activation'],authority_id=spec.authority_id,
            installation_id=spec.installation_id,namespace=spec.namespace_cohort[0],
            supervisor_spec_digest=spec.spec_digest,authority_process_original=authority.main_process_original,
            key_id=c09['key_id'],key_bytes=key)
        if request['registry_host_start']['control_store_id']!=c09['control_store_id']:
            raise AuthorityUnavailable('actual Host registry start names another protected Control')

    def _peer_start_hold_v3(self,channel,request,authority):
        from .c09_writer_peer_originals_v3 import (verify_writer_peer_pending_start_original_v3,
            verify_writer_peer_pending_start_completion_original_v3)
        from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
        role='host';spec=self.specs[role]
        before=self._observe(role)
        resolving=request['verb']=='peer_start_resolve_hold'
        covering=request['verb']=='peer_start_coverage_hold'
        if not resolving and not covering and (not before.stopped_and_drained or before.invocation_id!=request['expected_invocation_id']):
            raise AuthorityUnavailable('Root pending start requires its actual original complete stopped baseline')
        nonce=uuid4().hex
        files=InstalledPackageSelectionFilesV2(control_directory=self.specs['authority'].selection_control_directory)
        _,_,configuration=files.read_selected_configuration_cohort_v2()
        c09=configuration['assets']['c09_storage_v1']
        key=read_installed_bytes_v1(c09['key_path'],private=True,allowed_gid=0,limit=4096)
        def verify_pending(pending,host_start=None,activation=None):
            verify_writer_peer_pending_start_original_v3(pending,activation_original=activation,
                host_start_original=host_start,supervisor_spec_digest=spec.spec_digest,
                root_process_original=self.launcher_original,authority_process_original=authority.main_process_original,
                channel_nonce=None if resolving else nonce,key_id=c09['key_id'],key_bytes=key)
        pending=request.get('pending_start_original') if resolving else None
        if resolving:
            from .c09_writer_peer_originals_v3 import verify_writer_peer_pending_start_resolve_original_v3
            verify_writer_peer_pending_start_resolve_original_v3(pending,authority_id=spec.authority_id,
                installation_id=spec.installation_id,namespace=spec.namespace_cohort[0],
                supervisor_spec_digest=spec.spec_digest,root_process_original=self.launcher_original,
                key_id=c09['key_id'],key_bytes=key)
        channel.sendall(json.dumps(dict(status='peer_start_held',observation=asdict(before),root_channel_nonce=nonce,
            root_process_original=self.launcher_original,authority_process_original=authority.main_process_original),
            separators=(',',':')).encode()+b'\n')
        if covering:
            while True:
                packet=_read_peer_start_packet_v3(channel)
                if packet.get('root_channel_nonce')!=nonce:
                    raise AuthorityUnavailable('actual Root pending coverage channel identity differs')
                if packet.get('action')=='release_peer_start_coverage':
                    from .c09_writer_peer_originals_v3 import verify_writer_peer_pending_start_coverage_original_v3
                    verified=verify_writer_peer_pending_start_coverage_original_v3(packet['coverage_original'],
                        authority_id=spec.authority_id,installation_id=spec.installation_id,
                        namespace=spec.namespace_cohort[0],key_id=c09['key_id'],key_bytes=key)
                    if (verified['bootstrap_channel_nonce']!=nonce
                            or verified['bootstrap_root_process_original']!=self.launcher_original
                            or verified['bootstrap_authority_process_original']!=authority.main_process_original
                            or verified['maintenance_operation_id'] is not None):
                        raise AuthorityUnavailable('Root pending EOF ACK belongs to another actual bootstrap hold')
                    channel.sendall(json.dumps(dict(status='peer_start_coverage_released',root_channel_nonce=nonce),
                        separators=(',',':')).encode()+b'\n')
                    return
                if packet.get('action')=='ack_old_root_pending':
                    from .c09_writer_peer_originals_v3 import verify_writer_peer_old_root_retirement_original_v3
                    if set(packet)!={'action','root_channel_nonce','pending_start_original','retirement_original','completion_original'}:
                        raise AuthorityUnavailable('closed actual old Root custody ACK required')
                    old=packet['pending_start_original']
                    if old['root_process_original']==self.launcher_original:
                        raise AuthorityUnavailable('current Root cohort cannot use the old-cohort completion path')
                    if (old['authority_id']!=spec.authority_id or old['installation_id']!=spec.installation_id
                            or old['namespace'] not in spec.namespace_cohort):
                        raise AuthorityUnavailable('old Root custody ACK crosses the actual installed cohort')
                    verify_writer_peer_old_root_retirement_original_v3(packet['retirement_original'],pending_start_original=old,
                        key_id=c09['key_id'],key_bytes=key)
                    verify_writer_peer_pending_start_completion_original_v3(packet['completion_original'],
                        pending_start_original=old,key_id=c09['key_id'],key_bytes=key)
                    channel.sendall(json.dumps(dict(status='pending_peer_completed',root_channel_nonce=nonce),
                        separators=(',',':')).encode()+b'\n')
                    continue
                if set(packet)!={'action','root_channel_nonce','pending_start_original'} or packet['action']!='resolve_pending_peer':
                    raise AuthorityUnavailable('actual Root pending coverage resolve packet required')
                pending=packet['pending_start_original']
                from .c09_writer_peer_originals_v3 import verify_writer_peer_pending_start_resolve_original_v3
                verify_writer_peer_pending_start_resolve_original_v3(pending,authority_id=spec.authority_id,
                    installation_id=spec.installation_id,namespace=spec.namespace_cohort[0],
                    supervisor_spec_digest=spec.spec_digest,root_process_original=self.launcher_original,
                    key_id=c09['key_id'],key_bytes=key)
                current=self._observe(role)
                observed=current if current.stopped_and_drained else self._stop(role,current.invocation_id)
                channel.sendall(json.dumps(dict(status='peer_start_observed',root_channel_nonce=nonce,
                    pending_start_digest=pending['pending_start_digest'],observation=asdict(observed)),
                    separators=(',',':')).encode()+b'\n')
                ack=_read_peer_start_packet_v3(channel)
                if (set(ack)!={'action','root_channel_nonce','completion_original'}
                        or ack['action']!='complete_pending_peer' or ack['root_channel_nonce']!=nonce):
                    raise AuthorityUnavailable('actual original Root pending completion required before next coverage step')
                verify_writer_peer_pending_start_completion_original_v3(ack['completion_original'],
                    pending_start_original=pending,key_id=c09['key_id'],key_bytes=key)
                channel.sendall(json.dumps(dict(status='pending_peer_completed',root_channel_nonce=nonce),
                    separators=(',',':')).encode()+b'\n')
        if resolving:
            observed=before if before.stopped_and_drained else self._stop(role,before.invocation_id)
        else:
            packet=_read_peer_start_packet_v3(channel)
            if packet==dict(action='release_peer_start_hold',root_channel_nonce=nonce,completion_original=None):return
            if (set(packet)!={'action','root_channel_nonce','pending_start_original','registry_activation','registry_host_start'}
                    or packet['action']!='start_peer' or packet['root_channel_nonce']!=nonce):
                raise AuthorityUnavailable('same original Root peer-start hold packet required')
            pending=packet['pending_start_original']
            self._require_peer_registry_host_start_v3(packet,authority)
            verify_pending(pending,packet['registry_host_start'],packet['registry_activation'])
            observed=self._start(role,request['expected_invocation_id'])
        channel.sendall(json.dumps(dict(status='peer_start_observed',root_channel_nonce=nonce,
            pending_start_digest=pending['pending_start_digest'],observation=asdict(observed)),
            separators=(',',':')).encode()+b'\n')
        release=_read_peer_start_packet_v3(channel)
        if (set(release)!={'action','root_channel_nonce','completion_original'}
                or release['action']!='release_peer_start_hold' or release['root_channel_nonce']!=nonce):
            raise AuthorityUnavailable('actual original Root pending completion ACK required')
        verify_writer_peer_pending_start_completion_original_v3(release['completion_original'],
            pending_start_original=pending,key_id=c09['key_id'],key_bytes=key)
        channel.sendall(json.dumps(dict(status='peer_start_released',root_channel_nonce=nonce),
            separators=(',',':')).encode()+b'\n')

    def _start(self, role, expected_prior):
        before = self._observe(role)
        if self.retiring or not before.stopped_and_drained or before.invocation_id not in {"", expected_prior}:
            raise AuthorityUnavailable("fixed start requires original stopped/drained invocation")
        spec = self.specs[role]
        selected_invocation = _read_selected_invocation(spec, diagnostic_sequence=self._active_control_diagnostic_sequence)
        record = self.registry.pop(role, None)
        if record:
            os.close(record["pidfd"])
        process = subprocess.Popen(spec.fixed_argv, cwd=spec.fixed_cwd, env=spec.finite_environment_policy,
            stdin=subprocess.DEVNULL, shell=False, close_fds=True,
            preexec_fn=(lambda: _host_credentials(spec)) if role == "host" else (lambda: os.setgroups([])))
        original = read_process_identity_v1(process.pid)
        if original is None:
            raise AuthorityUnavailable("fixed child exited before live registration")
        self.registry[role] = dict(process=process, pidfd=self._pin(original), original=original,
                                   invocation=uuid4().hex, selected=selected_invocation)
        deadline = time.monotonic() + spec.start_timeout
        while time.monotonic() < deadline:
            try:
                after = self._observe(role)
                if after.state == "active":
                    return after
            except (AuthorityUnavailable, FileNotFoundError):
                if process.poll() is not None:
                    break
            time.sleep(0.02)
        raise AuthorityUnavailable("original fixed exec/start remains unqualified")

    def _stop(self, role, expected):
        before = self._observe(role)
        if before.invocation_id != expected:
            raise AuthorityUnavailable("fixed stop invocation changed")
        if before.stopped_and_drained:
            return before
        deadline = time.monotonic() + self.specs[role].drain_timeout
        escalate = time.monotonic() + self.specs[role].drain_timeout / 2
        while time.monotonic() < deadline:
            originals = self._inventory(role)
            for original in originals:
                try:
                    fd = self._pin(original)
                except (ProcessLookupError, FileNotFoundError):
                    continue
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL if time.monotonic() >= escalate else signal.SIGTERM)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(fd)
            after = self._observe(role)
            if after.stopped_and_drained:
                time.sleep(0.02)
                confirmed = self._observe(role)
                if confirmed.stopped_and_drained:
                    return confirmed
            time.sleep(0.02)
        raise AuthorityUnavailable("original stop outcome unknown: Host role not drained")

    def serve_forever_v1(self):
        endpoint = Path(self.specs["host"].control_socket_path)
        if endpoint.exists():
            info = endpoint.lstat()
            if not endpoint.is_socket() or info.st_uid != 0 or info.st_mode & 0o077:
                raise AuthorityUnavailable("existing control endpoint is not an installed root-only socket")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as prior:
                prior.settimeout(1)
                try:
                    prior.connect(str(endpoint))
                except ConnectionRefusedError:
                    # The lifetime lock excludes a live prior launch owner.
                    # Remove only its stale named socket, never recover its registry.
                    endpoint.unlink()
                else:
                    raise AuthorityUnavailable("existing control endpoint still has a live listener")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(endpoint))
        os.chmod(endpoint, 0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        signal.signal(signal.SIGTERM, lambda _signum, _frame: setattr(self, "retiring", True))
        signal.signal(signal.SIGINT, lambda _signum, _frame: setattr(self, "retiring", True))
        self._start("authority", "")
        exit_code = 0
        try:
            while not self.retiring:
                self._reap()
                if select.select([self.registry["authority"]["pidfd"]], [], [], 0)[0]:
                    # Independent Authority loss retires this namespace. Reopen
                    # is a new launcher invocation with normal durable recovery.
                    self._reap()
                    status = self.registry["authority"]["process"].returncode
                    exit_code = status if status is not None and status >= 0 else 128 + abs(status or signal.SIGKILL)
                    break
                try:
                    channel, _ = self.listener.accept()
                except socket.timeout:
                    continue
                self._control_diagnostic_sequence += 1
                self._active_control_diagnostic_sequence = self._control_diagnostic_sequence
                _supervisor_stage_event_v1("control_accepted", "accepted",
                    sequence=self._active_control_diagnostic_sequence)
                with _peer_start_channel_scope_v3(channel):
                    channel.settimeout(60)
                    result = {"status": "unavailable"}
                    try:
                        pid, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        _supervisor_stage_event_v1("control_peer", "observed",
                            sequence=self._active_control_diagnostic_sequence, peer_pid=pid)
                        with _supervisor_diagnostic_stage_v1("control_authority_observe",
                                sequence=self._active_control_diagnostic_sequence, role="authority"):
                            authority = self._observe("authority")
                        if (uid != 0 or pid != authority.main_pid or authority.state != "active"
                                or read_process_identity_v1(pid) != authority.main_process_original):
                            raise AuthorityUnavailable("control caller is not the live registered Authority")
                        with _supervisor_diagnostic_stage_v1("control_request_read",
                                sequence=self._active_control_diagnostic_sequence):
                            request=_read_peer_start_packet_v3(channel,limit=65536)
                        expected_fields={"verb", "service_role", "expected_invocation_id", "spec_digest"}
                        if request.get('verb')=='registry_genesis_hold':expected_fields.add('registry_scope')
                        elif request.get('verb')=='peer_start_resolve_hold':expected_fields.add('pending_start_original')
                        if set(request) != expected_fields:
                            raise AuthorityUnavailable("closed fixed control request required")
                        role = request["service_role"]
                        if role not in self.specs or request["spec_digest"] != self.specs[role].spec_digest:
                            raise AuthorityUnavailable("control installed service binding differs")
                        verb = request["verb"]
                        if role=='host' and verb=='registry_genesis_hold':
                            scope=request['registry_scope']
                            if (set(scope)!={'authority_id','installation_id','namespace','manifest_digest',
                                    'pointer_version','storage_generation','peer_cohort_digest'}
                                    or scope['authority_id']!=self.specs[role].authority_id
                                    or scope['installation_id']!=self.specs[role].installation_id
                                    or scope['namespace'] not in self.specs[role].namespace_cohort
                                    or scope['pointer_version']!=0 or scope['storage_generation']!=0
                                    or self.registry.get('host') is not None):
                                raise AuthorityUnavailable('actual first installed Host genesis scope unavailable')
                            observed=self._observe('host')
                            if not observed.stopped_and_drained:
                                raise AuthorityUnavailable('actual full Host UID census is not empty before first admission')
                            nonce=uuid4().hex
                            held={'status':'registry_genesis_held','observation':asdict(observed),
                                'root_channel_nonce':nonce,'root_process_original':self.launcher_original,
                                'authority_process_original':authority.main_process_original,'registry_scope':scope}
                            channel.sendall(json.dumps(held,separators=(',',':')).encode()+b'\n')
                            # This actual single control loop cannot dispatch a start while this channel is held.
                            with channel.makefile('rb') as stream:
                                release_raw=stream.readline(1025)
                            if len(release_raw)>1024 or not release_raw.endswith(b'\n'):
                                raise AuthorityUnavailable('Root genesis exclusion release channel ended')
                            release=json.loads(release_raw)
                            if release!={'root_channel_nonce':nonce,'action':'release_registry_genesis'}:
                                raise AuthorityUnavailable('Root genesis exclusion release identity differs')
                            continue
                        if role=='host' and verb in {'peer_start_hold','peer_start_resolve_hold','peer_start_coverage_hold'}:
                            self._peer_start_hold_v3(channel,request,authority)
                            continue
                        if verb == "observe":
                            with _supervisor_diagnostic_stage_v1("control_role_observe",
                                    sequence=self._active_control_diagnostic_sequence, role=role):
                                observed = self._observe(role)
                        elif role == "host" and verb == "stop":
                            observed = self._stop(role, request["expected_invocation_id"])
                        else:
                            raise AuthorityUnavailable("Authority retirement requires the fixed PID1 maintenance controller")
                        result = {"status": "observed", "observation": asdict(observed)}
                    except (AuthorityUnavailable, OSError, ValueError) as exc:
                        diagnostic = traceback.TracebackException.from_exception(exc, capture_locals=False)
                        chain = []
                        while diagnostic is not None:
                            chain.append({"type": diagnostic.exc_type.__name__, "frames": [
                                {"file": frame.filename, "line": frame.lineno, "function": frame.name}
                                for frame in diagnostic.stack]})
                            diagnostic = diagnostic.__cause__ or (
                                None if diagnostic.__suppress_context__ else diagnostic.__context__)
                        logging.getLogger(__name__).error(
                            "Sylanne D12 root launcher cause metadata: " +
                            json.dumps(chain, separators=(",", ":")))
                        result = {"status": "unavailable", "reason": str(exc)}
                    try:
                        with _supervisor_diagnostic_stage_v1("control_response_send",
                                sequence=self._active_control_diagnostic_sequence):
                            channel.sendall(json.dumps(result, separators=(",", ":")).encode() + b"\n")
                    except (BrokenPipeError, ConnectionResetError):
                        # A lost ACK does not forget the actual launch/stop.
                        pass
                self._active_control_diagnostic_sequence = None
        finally:
            self.retiring = True
            self.listener.close()
            endpoint.unlink(missing_ok=True)
            os.close(self.lease_fd)
            # PID1 exit is whole-namespace retirement, not a Host pause receipt.
        return exit_code


class InstalledRootProcessSupervisorV1:
    def __init__(self, *, config: InstalledProcessSupervisorSpecV2):
        verify_process_supervisor_spec_v1(config)
        if os.geteuid() != 0:
            raise AuthorityUnavailable("independent root supervisor adapter required")
        self.config = config
        self._peer_registry_control_v3=None
        self._peer_registry_gate_v3=None
        self._pending_peer_start_v3=None

    def install_peer_registry_start_v3(self, *, control, gate):
        from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
        if (type(gate) is not InstalledC09WriterGateV1 or gate.control is not control
                or control.installation_id!=self.config.installation_id
                or control.authority_id!=self.config.authority_id
                ):
            raise AuthorityUnavailable('actual installed production Host registry start binding required')
        if self._peer_registry_control_v3 is control and self._peer_registry_gate_v3 is gate:return
        if self._peer_registry_control_v3 is not None:
            old_control,old_gate=self._peer_registry_control_v3,self._peer_registry_gate_v3
            if (self._pending_peer_start_v3 is not None or old_gate._active
                    or old_gate._installed_config_v3 is not gate._installed_config_v3
                    or (old_control.authority_id,old_control.installation_id,old_control.control_store_id,old_control.path)
                       !=(control.authority_id,control.installation_id,control.control_store_id,control.path)):
                raise AuthorityUnavailable('actual previous Root adapter must drain before same-installation recomposition')
        self._peer_registry_control_v3,self._peer_registry_gate_v3=control,gate
        gate.install_pending_start_supervisor_v3(self)

    def _request(self, verb, expected=""):
        verify_process_supervisor_spec_v1(self.config)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(max(self.config.start_timeout, self.config.drain_timeout) + 2)
            endpoint = Path(self.config.control_socket_path)
            info = endpoint.lstat()
            if not endpoint.is_socket() or info.st_uid != 0 or info.st_mode & 0o077:
                raise AuthorityUnavailable("root-only launcher socket required")
            channel.connect(str(endpoint))
            pid, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if (pid != 1 or uid != 0 or _namespace_identity(pid, "pid") != _namespace_identity(os.getpid(), "pid")
                    or _namespace_identity(pid, "mnt") != _namespace_identity(os.getpid(), "mnt")):
                raise AuthorityUnavailable("actual root PID1/namespace launcher peer required")
            launcher = read_process_identity_v1(pid)
            request=dict(verb=verb,service_role=self.config.service_role,expected_invocation_id=expected,
                spec_digest=self.config.spec_digest)
            if verb=='start':
                control,gate=self._peer_registry_control_v3,self._peer_registry_gate_v3
                if control is None or gate is None:
                    raise AuthorityUnavailable('actual signed production Host registry start binding absent')
                activation=control.read_writer_peer_registry_activation_v3()
                if activation is None:
                    raise AuthorityUnavailable('production Host has no signed peer registry activation')
                request['registry_activation']=activation.original
                request['registry_host_start']=control.read_writer_peer_registry_host_start_original_v3(gate,
                    supervisor_spec_digest=self.config.spec_digest)
            channel.sendall(json.dumps(request,separators=(',',':')).encode()+b'\n')
            with channel.makefile("rb") as stream:
                raw = stream.readline(262145)
            if len(raw) > 262144 or not raw.endswith(b"\n"):
                raise AuthorityUnavailable("bounded actual launcher observation required")
            response = json.loads(raw)
        if response.get("status") != "observed":
            raise AuthorityUnavailable(response.get("reason", "launcher observation unavailable"))
        observed = decode_process_supervisor_observation_v2(response["observation"])
        if (observed.supervisor_id != self.config.supervisor_id or observed.spec_digest != self.config.spec_digest
                or observed.service_role != self.config.service_role or observed.launcher_process_original != launcher):
            raise AuthorityUnavailable("live launcher observation binding differs")
        return observed

    @contextmanager
    def hold_peer_registry_genesis_v3(self, *, registry_scope):
        verify_process_supervisor_spec_v1(self.config)
        if self.config.service_role!='host':
            raise AuthorityUnavailable('installed Host Root genesis provider required')
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        hold=None
        try:
            channel.settimeout(max(self.config.start_timeout,self.config.drain_timeout)+2)
            endpoint=Path(self.config.control_socket_path)
            info=endpoint.lstat()
            if not endpoint.is_socket() or info.st_uid!=0 or info.st_mode&0o077:
                raise AuthorityUnavailable('actual root-only genesis endpoint required')
            channel.connect(str(endpoint))
            pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if (pid!=1 or uid!=0 or _namespace_identity(pid,'pid')!=_namespace_identity(os.getpid(),'pid')
                    or _namespace_identity(pid,'mnt')!=_namespace_identity(os.getpid(),'mnt')):
                raise AuthorityUnavailable('actual Root PID1 genesis channel namespace differs')
            launcher=read_process_identity_v1(pid);authority=read_process_identity_v1(os.getpid())
            channel.sendall(json.dumps({'verb':'registry_genesis_hold','service_role':'host',
                'expected_invocation_id':'','spec_digest':self.config.spec_digest,
                'registry_scope':registry_scope},separators=(',',':')).encode()+b'\n')
            with channel.makefile('rb') as stream:raw=stream.readline(262145)
            if len(raw)>262144 or not raw.endswith(b'\n'):
                raise AuthorityUnavailable('bounded complete Root genesis census original required')
            response=json.loads(raw)
            if response.get('status')!='registry_genesis_held' or response.get('registry_scope')!=registry_scope:
                raise AuthorityUnavailable(response.get('reason','Root genesis census scope unavailable'))
            hold=RootPeerRegistryGenesisHoldV3(_ROOT_GENESIS_HOLD_ISSUER_V3,self,channel,response,launcher,authority)
            hold.require_current()
            yield hold
        finally:
            if hold is not None:hold.close()
            else:channel.close()

    def read_current_host_state_v1(self):
        return self._request("observe")

    def stop_original_host_v1(self, *, expected_invocation_id):
        pending=self._pending_peer_start_v3
        if pending is not None and pending['original'] is not None:
            cap=self.resolve_pending_peer_start_v3(pending['original'])
            control=self._peer_registry_control_v3
            completion=control.read_writer_peer_pending_start_completion_v3(self._peer_registry_gate_v3,
                pending_start_original=pending['original'])
            if completion is None:
                completion=control.complete_writer_peer_pending_start_v3(self._peer_registry_gate_v3,observed_start=cap)
            cap.baseline.close(completion)
            observed=cap.observation
        else:
            if pending is not None and pending['baseline'] is not None:
                if pending['baseline'].start_sent:
                    raise AuthorityUnavailable('unknown dispatched Host start lacks its durable original identity')
                _close_peer_start_channel_v3(pending['baseline'].channel);pending['baseline'].closed=True
            observed=self._request('stop',expected_invocation_id)
        if not observed.stopped_and_drained:
            raise AuthorityUnavailable('fixed role has not actually stopped and drained')
        if pending is not None:
            self._pending_peer_start_v3=None
            pending['admission'].__exit__(None,None,None)
        return observed

    def _register_observed_started_peer_v3(self, pending, observed):
        spec=self.config
        if (observed.service_role!='host' or observed.spec_digest!=spec.spec_digest
                or observed.main_process_original is None
                or read_process_identity_v1(observed.main_pid)!=observed.main_process_original):
            raise AuthorityUnavailable('actual Root-created Host process/cohort is not currently observed')
        gate=self._peer_registry_gate_v3
        context=gate._current_context_v3(action='business',verify_files=False)
        if (context.manifest['cohort_namespaces']!=list(spec.namespace_cohort)
                or context.manifest['installation_id']!=spec.installation_id
                or context.manifest['authority_id']!=spec.authority_id):
            raise AuthorityUnavailable('actual Root-created Host belongs to another selected namespace cohort')
        return gate.register_peer_process_v1(peer=pending['peer'],process_id=observed.main_pid,
            process_incarnation='linux-host:'+observed.main_process_original['birth'],
            pointer_version=context.pointer_version,storage_generation=context.storage_generation)

    def _open_peer_start_baseline_v3(self,*,expected_prior_invocation_id,pending=None,coverage=False):
        gate=self._peer_registry_gate_v3
        if gate is None:raise AuthorityUnavailable('actual Root peer-start Gate is not installed')
        peers=tuple(peer for peer,item in gate._installed_config_v3.installations_v2.items()
            if peer[1]==self.config.profile_id and item.installation_id==self.config.installation_id)
        if len(peers)!=1:raise AuthorityUnavailable('actual Root installed peer binding is ambiguous')
        verify_process_supervisor_spec_v1(self.config)
        endpoint=Path(self.config.control_socket_path);st=endpoint.lstat()
        if not endpoint.is_socket() or st.st_uid!=0 or st.st_mode&0o077:
            raise AuthorityUnavailable('actual Root-only pending start endpoint required')
        channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            channel.settimeout(60);channel.connect(str(endpoint))
            pid,uid,_=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if (pid!=1 or uid!=0 or _namespace_identity(pid,'pid')!=_namespace_identity(os.getpid(),'pid')
                    or _namespace_identity(pid,'mnt')!=_namespace_identity(os.getpid(),'mnt')):
                raise AuthorityUnavailable('actual installed Root namespace/peer required for pending start')
            root=read_process_identity_v1(pid);authority=read_process_identity_v1(os.getpid())
            request=dict(verb='peer_start_coverage_hold' if coverage else 'peer_start_hold' if pending is None else 'peer_start_resolve_hold',service_role='host',
                expected_invocation_id=expected_prior_invocation_id,spec_digest=self.config.spec_digest)
            if pending is not None:request['pending_start_original']=pending
            channel.sendall(json.dumps(request,separators=(',',':')).encode()+b'\n')
            response=_read_peer_start_packet_v3(channel)
            cls=RootPeerStartCoverageHoldV3 if coverage else RootPeerStartBaselineV3
            baseline=cls(_ROOT_PEER_START_ISSUER_V3,supervisor=self,channel=channel,
                response=response,peer=peers[0],root=root,authority=authority)
            if pending is None and not coverage and (not baseline.observation.stopped_and_drained
                    or baseline.observation.invocation_id!=expected_prior_invocation_id):
                raise AuthorityUnavailable('Root pending start baseline differs from its original expected invocation')
            return baseline
        except BaseException:
            _close_peer_start_channel_v3(channel);raise

    def hold_pending_peer_start_coverage_v3(self):
        return self._open_peer_start_baseline_v3(expected_prior_invocation_id='',coverage=True)

    def require_pending_peer_start_baseline_v3(self,expected_prior_invocation_id):
        return self._open_peer_start_baseline_v3(expected_prior_invocation_id=expected_prior_invocation_id)

    def resolve_pending_peer_start_v3(self,pending_original):
        original_state=self._pending_peer_start_v3
        if original_state is not None and original_state['baseline'] is not None:
            prior=original_state['baseline'];_close_peer_start_channel_v3(prior.channel);prior.closed=True
        baseline=self._open_peer_start_baseline_v3(expected_prior_invocation_id=pending_original['expected_prior_invocation_id'],
            pending=pending_original)
        try:
            observed=baseline.observe_response_v3(pending_original)
            if not observed.stopped_and_drained:
                raise AuthorityUnavailable('actual cold Root pending Host cohort has not fully retired')
            return RootObservedPeerStartV3(_ROOT_PEER_START_ISSUER_V3,baseline=baseline,pending=pending_original,
                observation=observed,admission=None)
        except BaseException:
            _close_peer_start_channel_v3(baseline.channel);baseline.closed=True;raise

    def start_stopped_host_v1(self, *, expected_prior_invocation_id):
        gate=self._peer_registry_gate_v3
        if gate is None:raise AuthorityUnavailable('actual production Host start Gate absent')
        pending=self._pending_peer_start_v3
        if pending is not None:
            if pending['expected_prior']!=expected_prior_invocation_id:
                raise AuthorityUnavailable('unknown original Host start cannot be replaced by another invocation')
            if pending['original'] is None:
                self.stop_original_host_v1(expected_invocation_id=expected_prior_invocation_id)
                raise AuthorityUnavailable('undispatched original start has been observed retired; pending ledger requires EOF recovery')
            cap=self.resolve_pending_peer_start_v3(pending['original'])
            control=self._peer_registry_control_v3
            completion=control.read_writer_peer_pending_start_completion_v3(gate,pending_start_original=pending['original'])
            if completion is None:completion=control.complete_writer_peer_pending_start_v3(gate,observed_start=cap)
            cap.baseline.close(completion)
            self._pending_peer_start_v3=None
            pending['admission'].__exit__(None,None,None)
            raise AuthorityUnavailable('actual original pending Host start was retired; no second start dispatched')
        peers=tuple(peer for peer,item in gate._installed_config_v3.installations_v2.items()
            if peer[1]==self.config.profile_id and item.installation_id==self.config.installation_id)
        if len(peers)!=1:raise AuthorityUnavailable('actual installed Root Host peer is ambiguous')
        gate.retire_previous_peer_before_host_start_v3(peer=peers[0])
        context=gate._current_context_v3(action='business',verify_files=False)
        authority=read_process_identity_v1(os.getpid())
        admission=gate.admit_writer_v1(pointer_version=context.pointer_version,storage_generation=context.storage_generation,
            process_incarnation='root-host-start:'+authority['birth'])
        admission.__enter__()
        state=dict(admission=admission,peer=peers[0],expected_prior=expected_prior_invocation_id,baseline=None,original=None)
        self._pending_peer_start_v3=state
        baseline=self.require_pending_peer_start_baseline_v3(expected_prior_invocation_id)
        state['baseline']=baseline
        control=self._peer_registry_control_v3
        activation=control.read_writer_peer_registry_activation_v3().original
        host_start=control.read_writer_peer_registry_host_start_original_v3(gate,supervisor_spec_digest=self.config.spec_digest)
        original=control.retain_writer_peer_pending_start_v3(gate,supervisor=self,host_start_original=host_start,
            expected_prior_invocation_id=expected_prior_invocation_id,baseline=baseline)
        state['original']=original
        observed=baseline.start_v3(pending=original,activation=activation,host_start=host_start)
        durable=self._register_observed_started_peer_v3(state,observed)
        cap=RootObservedPeerStartV3(_ROOT_PEER_START_ISSUER_V3,baseline=baseline,pending=original,
            observation=observed,admission=durable)
        completion=control.complete_writer_peer_pending_start_v3(gate,observed_start=cap)
        baseline.close(completion)
        self._pending_peer_start_v3=None
        admission.__exit__(None,None,None)
        if observed.state!='active' or observed.invocation_id==expected_prior_invocation_id:
            raise AuthorityUnavailable('actual durably registered born Host has no distinct active invocation')
        return observed

    def require_admitted_peer_v1(self, *, actual_socket_peer):
        pid, uid, gid = actual_socket_peer
        observed = self.read_current_host_state_v1()
        selected = _read_selected_invocation(self.config)
        if (self.config.service_role != "host" or uid != self.config.expected_uid or gid != self.config.expected_gid
                or observed.state != "active" or observed.main_pid != pid
                or read_process_identity_v1(pid) != observed.main_process_original
                or any(getattr(observed, name) != value for name, value in selected.items())):
            raise AuthorityUnavailable("socket peer is not the actual registered non-root Host main")
        return observed
