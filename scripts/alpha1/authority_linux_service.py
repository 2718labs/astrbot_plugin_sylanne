"""Installed Linux Authority service. Run under the supplied systemd unit."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import signal
import sys
sys.dont_write_bytecode = True
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


async def run(config, *, selection_revision=None, cohort_digest=None):
    from sylanne3.authority_service.linux_deployment_v1 import open_linux_authority_v1, install_linux_lifecycle_v1
    from sylanne3.authority_service.linux_host_supervisor_v1 import InstalledLinuxHostSupervisorV1
    from sylanne3.authority_service.contract import AuthorityColdRestartRequired
    bootstrap,launch=open_linux_authority_v1(config)
    try:
        daemon=await bootstrap.await_business_ready_v3()
    except AuthorityColdRestartRequired:
        await bootstrap.aclose()
        return 75
    except BaseException:
        await bootstrap.aclose()
        raise
    bundles = tuple(item.installation_bundle for item in daemon.config.natural_model_authorities_v2.values())
    if len(bundles) != 1:
        await daemon.aclose()
        raise RuntimeError('exact selected Authority configuration cohort required')
    selected = bundles[0].package_selection
    if ((selected is None) != (selection_revision is None and cohort_digest is None)
            or selected is not None and (selected.revision != selection_revision or selected.cohort_digest != cohort_digest)):
        await daemon.aclose()
        raise RuntimeError('fixed launcher selection differs from actual Authority configuration')
    daemon.server._package_selection_v2 = selected
    stop = threading.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    if launch["schema"] == "sylanne3.authority.linux-deployment.v2":
        from sylanne3.authority_service.d12_installed_supervisor_v1 import (
            build_installed_supervisor_v1, decode_installed_supervisor_config_v1)
        host_provider = build_installed_supervisor_v1(decode_installed_supervisor_config_v1(launch["host_supervisor_provider"]))
        supervisor = InstalledLinuxHostSupervisorV1(daemon=daemon, socket_path=launch["admission_socket"],
            host_uid=launch["host_uid"], host_gid=launch["host_gid"], process_supervisor=host_provider)
    else:
        supervisor = InstalledLinuxHostSupervisorV1(daemon=daemon, socket_path=launch["admission_socket"],
            host_uid=launch["host_uid"], host_gid=launch["host_gid"], systemd_unit=launch["host_systemd_unit"])
    try:
        lifecycle = install_linux_lifecycle_v1(daemon, launch)
        await daemon.start()
        await supervisor.start()
        lifecycle.resume_pending_operations_v1()
        await supervisor.start_host()
        daemon._resolved_storage_composition_v3.require_current()
        current=daemon._resolved_storage_composition_v3.context
        print(json.dumps({"event": "ready", "authority_id": current.manifest["authority_id"],
            "pointer_version": current.pointer_version, "storage_generation": current.storage_generation,
            "stage": current.stage, "package_selection_revision": selection_revision,
            "configuration_cohort_digest": cohort_digest}), flush=True)
        return 75 if await daemon.wait_until_stopped_v1(stop) else 0
    finally:
        await supervisor.aclose()
        await daemon.aclose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/sylanne/authority/deployment.json"))
    parser.add_argument('--selection-revision', type=int)
    parser.add_argument('--cohort-digest')
    args = parser.parse_args()
    if ((args.selection_revision is None) != (args.cohort_digest is None)
            or args.selection_revision is not None and args.selection_revision < 0):
        parser.error('selection revision and cohort digest must be supplied together')
    raise SystemExit(asyncio.run(run(args.config, selection_revision=args.selection_revision, cohort_digest=args.cohort_digest)))


if __name__ == "__main__":
    main()
