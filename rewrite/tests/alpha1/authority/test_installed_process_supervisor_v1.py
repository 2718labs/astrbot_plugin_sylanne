"""Real Linux pidfd races at the source observer seam, not installed Host proof.

Children, birth reads, pidfds and readiness are real. Protected spec/selection
verification and the inventory universe are explicit unit seams; this harness
has no PID1 launcher, installation authorization, or arbitrary UID sweep.
"""
from dataclasses import asdict
from hashlib import sha256
import os
from pathlib import Path
import select
import subprocess
import sys

import pytest

from sylanne3.authority_service import installed_process_supervisor_v1 as provider
from sylanne3.authority_service.contract import AuthorityUnavailable


pytestmark = pytest.mark.skipif(not hasattr(os, "pidfd_open"), reason="Linux pidfd required")


@pytest.fixture
def owned_children(tmp_path):
    entry = tmp_path / "owned_child.py"
    entry.write_text("import sys\nsys.stdout.write('ready\\n')\nsys.stdout.flush()\nsys.stdin.buffer.read(1)\n")
    children = []

    def launch():
        child = subprocess.Popen([sys.executable, "-B", str(entry)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        assert select.select([child.stdout], [], [], 10)[0]
        assert child.stdout.readline() == b"ready\n"
        return child

    yield entry, launch
    for child in children:
        if child.poll() is None:
            child.kill()  # Only the actual Popen owned by this fixture.
        child.wait(timeout=10)
        child.stdin.close()
        child.stdout.close()
        child.stderr.close()


def _finish(child):
    child.stdin.write(b"x")
    child.stdin.flush()
    assert child.wait(timeout=10) == 0


class _ObservationHarness:
    _observe = provider.RootProcessLauncherV1._observe

    def __init__(self, spec, selected, main, members):
        self.specs = {spec.service_role: spec}
        self.registry = {spec.service_role: dict(process=main, pidfd=os.pidfd_open(main.pid),
            original=provider.read_process_identity_v1(main.pid), invocation="unit-invocation", selected=selected)}
        self.members = members
        self.identity_reader = provider.read_process_identity_v1
        self.launcher_original = self.identity_reader(os.getpid())
        self.pid_namespace = os.readlink("/proc/self/ns/pid")
        self.mount_namespace = os.readlink("/proc/self/ns/mnt")
        self.sequence = 0
        self.inventory_calls = 0

    def _inventory(self, role):
        assert role in self.specs
        self.inventory_calls += 1
        # The real installed implementation checks every role UID process.
        # This source seam measures only the two explicit owned test children.
        return tuple(sorted((identity for child in self.members
            if (identity := self.identity_reader(child.pid)) is not None), key=lambda value: value["pid"]))


def _observer(monkeypatch, tmp_path, entry, main, members):
    executable = str(Path(sys.executable).resolve())
    entry_digest = sha256(entry.read_bytes()).hexdigest()
    role = "authority" if os.getuid() == 0 else "host"
    spec = provider.InstalledProcessSupervisorSpecV2(
        schema="sylanne3.installed-process-supervisor.v2", provider_kind=provider.KIND,
        supervisor_id="unit-supervisor", installation_id="unit-installation", authority_id="unit-authority",
        profile_id="unit-profile", namespace_cohort=("unit-namespace",), service_role=role,
        installed_spec_path=str(tmp_path / "spec.json"), launcher_code_ref=str(Path(__file__).resolve()),
        launcher_build_digest="a" * 64, fixed_executable_path=executable,
        executable_sha256=sha256(Path(executable).read_bytes()).hexdigest(), fixed_entry_ref=str(entry),
        entry_sha256=entry_digest, fixed_argv=(executable, "-B", str(entry)), fixed_cwd=str(tmp_path),
        finite_environment_policy={}, expected_uid=os.getuid(), expected_gid=os.getgid(),
        supplementary_group_policy="drop_all", bootstrap_package_ref="bootstrap:" + "b" * 64,
        selection_control_directory="/etc/sylanne/maintenance", control_socket_path=str(tmp_path / "control.sock"),
        protected_state_directory=str(tmp_path), maximum_processes=2, start_timeout=1, drain_timeout=1)
    selected = dict(selection_revision=1, selected_cohort_digest="c" * 64, selected_release_ref="unit-release",
        selected_manifest_digest="d" * 64, launch_entry_ref=str(entry), launch_entry_sha256=entry_digest,
        launch_argv=spec.fixed_argv, expected_final_entry=str(entry), expected_final_entry_sha256=entry_digest,
        expected_final_argv=spec.fixed_argv)
    checks = []

    def verify_spec_seam(value):
        assert value is spec
        checks.append("spec")

    def selected_registry_seam(value):
        assert value is spec
        checks.append("selection")
        return selected

    monkeypatch.setattr(provider, "verify_process_supervisor_spec_v1", verify_spec_seam)
    monkeypatch.setattr(provider, "_read_selected_invocation", selected_registry_seam)
    return _ObservationHarness(spec, selected, main, members), role, checks


def test_owned_exit_between_pidfd_poll_and_identity_rechecks_full_inventory(monkeypatch, tmp_path, owned_children):
    entry, launch = owned_children
    main, residual = launch(), launch()
    observer, role, checks = _observer(monkeypatch, tmp_path, entry, main, [main, residual])
    record = observer.registry[role]
    actual_reader = provider.read_process_identity_v1
    identity_calls = []

    def exit_before_identity_read(pid):
        assert pid == main.pid
        identity_calls.append(pid)
        assert select.select([record["pidfd"]], [], [], 0)[0] == []
        _finish(main)
        assert select.select([record["pidfd"]], [], [], 0)[0] == [record["pidfd"]]
        return actual_reader(pid)

    monkeypatch.setattr(provider, "read_process_identity_v1", exit_before_identity_read)
    try:
        observed = observer._observe(role)
        assert identity_calls == [main.pid]
        assert observer.inventory_calls == 2
        assert checks == ["spec", "selection", "spec"]
        assert observed.state == "draining" and observed.main_pid == 0
        assert observed.process_ids == (residual.pid,)
        assert not observed.stopped_and_drained
        assert provider.decode_process_supervisor_observation_v2(asdict(observed)) == observed
        _finish(residual)
        stopped = observer._observe(role)
        assert stopped.stopped_and_drained and stopped.process_ids == ()
        assert observer.inventory_calls == 3
    finally:
        os.close(record["pidfd"])


def test_alive_original_pidfd_rejects_different_saved_birth(monkeypatch, tmp_path, owned_children):
    entry, launch = owned_children
    main = launch()
    observer, role, checks = _observer(monkeypatch, tmp_path, entry, main, [main])
    record = observer.registry[role]
    parent_original = provider.read_process_identity_v1(os.getpid())
    assert parent_original["birth"] != record["original"]["birth"]
    record["original"] = {**record["original"], "birth": parent_original["birth"]}
    try:
        assert select.select([record["pidfd"]], [], [], 0)[0] == []
        with pytest.raises(AuthorityUnavailable, match="registered main process birth changed"):
            observer._observe(role)
        assert select.select([record["pidfd"]], [], [], 0)[0] == []
        assert main.poll() is None
        assert observer.inventory_calls == 1
        assert checks == ["spec", "selection"]
    finally:
        os.close(record["pidfd"])
