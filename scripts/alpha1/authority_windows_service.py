"""Windows Authority foreground/SCM process using fixed installed callbacks.

The publisher key and exact package/manifest pins come from installer-owned
arguments. Current bundles remain diagnostic staging; this process does not
grant publisher enrollment or claim a formal product installation.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import threading
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_installer import verify_publisher_bundle


SERVICE_NAME = "SylanneAuthority"


def _installed_daemon(args):
    package = args.package.resolve(strict=True)
    code = args.code.resolve(strict=True)
    assets = args.assets.resolve(strict=True)
    if assets.is_relative_to(code):
        raise ValueError("Authority state/assets must be separate from code")
    verified = verify_publisher_bundle(
        package, args.signature, args.publisher_key,
        trusted_root_sha256=args.trusted_root_sha256,
        expected_package_sha256=args.expected_package_sha256,
        expected_manifest_sha256=args.expected_manifest_sha256,
    )
    with zipfile.ZipFile(package) as archive:
        manifest = json.loads(archive.read("authority-staging-manifest.json"))
        for row in manifest["files"]:
            path = code / row["path"]
            if not path.is_file() or path.is_symlink() or path.read_bytes() != archive.read(row["path"]):
                raise ValueError("installed Authority code differs from signed bundle")
    sys.path.insert(0, str(code))
    from rewrite.sylanne3.authority_service.daemon import open_authority_daemon
    from rewrite.sylanne3.authority_service.deployment_config import load_installed_asset_config_v1
    from rewrite.sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from rewrite.sylanne3.authority_service.installed_policy import (
        InstalledAuthorityPolicyV1, InstalledPeerScopeV1,
    )
    from rewrite.sylanne3.runtime_contracts import NamespaceId
    from rewrite.sylanne3.graph_coordinator import namespace_ref

    rows = json.loads(assets.read_bytes())
    installation_by_peer = {
        (row["certificate_sha256"], row["profile_id"]): row
        for row in rows["installations_v2"]
    }
    scopes = {}
    for row in rows["namespace_bindings_v2"]:
        peer = (row["certificate_sha256"], row["profile_id"])
        installation = installation_by_peer[peer]
        namespace = namespace_ref(NamespaceId(row["bot_id"], row["persona_id"]))
        if namespace != row["authority_namespace"]:
            raise ValueError("installed namespace identity differs")
        scope = InstalledPeerScopeV1(namespace, installation["administrator_holder"])
        existing = scopes.get(peer[0])
        if existing is not None and existing != scope:
            raise ValueError("one certificate spans different installed Owner scopes")
        scopes[peer[0]] = scope
    policy = InstalledAuthorityPolicyV1(scopes)
    config = load_installed_asset_config_v1(
        assets, core_authorizer=policy.core_authorizer,
        core_verifier_factory=installed_core_verifier_factory,
        administrator_authorizer=policy.administrator_authorizer,
        publisher_manifest_verifier=policy.publisher_manifest_verifier,
        utc_clock=lambda: datetime.now(timezone.utc),
        local_administrator_credential=policy.local_administrator_credential,
    )
    return open_authority_daemon(config), verified


async def _run(args, stop: threading.Event, on_running) -> None:
    daemon, verified = _installed_daemon(args)
    restart_required = False
    try:
        restart_required = await daemon.resume_cold_maintenance_v1()
        if restart_required:
            return
        with daemon.deletion.freeze_writes():
            deletion_head = daemon.deletion.verified_head()
        execution_heads = {
            namespace: journal.verified_head().digest
            for namespace, journal in daemon.execution.items()
        }
        authority_id = daemon.core._db.execute(
            "SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()[0]
        await daemon.start()
        on_running()
        print(json.dumps({
            "status": "diagnostic_only", "event": "ready",
            "package_sha256": verified["package_sha256"],
            "publisher_root": "supplied_pinned_key_not_product_root",
            "port": daemon.config.bind_port,
            "pid": os.getpid(),
            "authority_id": authority_id,
            "graph_reopened": True,
            "deletion_head": deletion_head.digest,
            "execution_heads": execution_heads,
        }), flush=True)
        restart_required = await daemon.wait_until_stopped_v1(stop)
    finally:
        await daemon.aclose()
        print(json.dumps({"status": "diagnostic_only", "event": "closed"}), flush=True)
        if restart_required:
            raise RuntimeError("C09 restart_required; restart the Authority service in a new process")


def _run_scm(args) -> None:
    if sys.platform != "win32":
        raise RuntimeError("SCM service requires Windows")
    import ctypes
    from ctypes import wintypes

    SERVICE_WIN32_OWN_PROCESS = 0x10
    SERVICE_STOPPED = 1
    SERVICE_START_PENDING = 2
    SERVICE_STOP_PENDING = 3
    SERVICE_RUNNING = 4
    SERVICE_ACCEPT_STOP = 1
    SERVICE_CONTROL_STOP = 1

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwCurrentState", wintypes.DWORD),
            ("dwControlsAccepted", wintypes.DWORD),
            ("dwWin32ExitCode", wintypes.DWORD),
            ("dwServiceSpecificExitCode", wintypes.DWORD),
            ("dwCheckPoint", wintypes.DWORD),
            ("dwWaitHint", wintypes.DWORD),
        ]

    SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD,
                                     ctypes.POINTER(ctypes.c_wchar_p))
    HANDLER = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD,
                                wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)

    class SERVICE_TABLE_ENTRY(ctypes.Structure):
        _fields_ = [("lpServiceName", ctypes.c_wchar_p),
                    ("lpServiceProc", SERVICE_MAIN)]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.RegisterServiceCtrlHandlerExW.argtypes = (
        ctypes.c_wchar_p, HANDLER, ctypes.c_void_p)
    advapi.RegisterServiceCtrlHandlerExW.restype = ctypes.c_void_p
    advapi.SetServiceStatus.argtypes = (ctypes.c_void_p, ctypes.POINTER(SERVICE_STATUS))
    advapi.SetServiceStatus.restype = wintypes.BOOL
    advapi.StartServiceCtrlDispatcherW.argtypes = (ctypes.POINTER(SERVICE_TABLE_ENTRY),)
    advapi.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    stop = threading.Event()
    handle = None
    callbacks = []

    def status(state: int, *, error: int = 0) -> None:
        value = SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS, state,
            SERVICE_ACCEPT_STOP if state == SERVICE_RUNNING else 0,
            error, 0, 0, 20_000 if state in {SERVICE_START_PENDING, SERVICE_STOP_PENDING} else 0,
        )
        if not advapi.SetServiceStatus(handle, ctypes.byref(value)):
            raise OSError(ctypes.get_last_error(), "SetServiceStatus failed")

    @HANDLER
    def handler(control, event_type, event_data, context):
        if control == SERVICE_CONTROL_STOP:
            status(SERVICE_STOP_PENDING)
            stop.set()
        return 0

    @SERVICE_MAIN
    def main(argc, argv):
        nonlocal handle
        handle = advapi.RegisterServiceCtrlHandlerExW(SERVICE_NAME, handler, None)
        if not handle:
            return
        status(SERVICE_START_PENDING)
        try:
            asyncio.run(_run(args, stop, lambda: status(SERVICE_RUNNING)))
        except BaseException:
            status(SERVICE_STOPPED, error=1)
            raise
        status(SERVICE_STOPPED)

    callbacks.extend((handler, main))
    table = (SERVICE_TABLE_ENTRY * 2)()
    table[0] = SERVICE_TABLE_ENTRY(SERVICE_NAME, main)
    table[1] = SERVICE_TABLE_ENTRY(None, SERVICE_MAIN())
    if not advapi.StartServiceCtrlDispatcherW(table):
        raise OSError(ctypes.get_last_error(), "StartServiceCtrlDispatcher failed")


def main() -> None:
    parser = argparse.ArgumentParser(description="Pinned Windows Authority daemon process")
    parser.add_argument("mode", choices=("console", "service"))
    for name in ("code", "assets", "package", "signature", "publisher-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("trusted-root-sha256", "expected-package-sha256",
                 "expected-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.mode == "service":
        _run_scm(args)
    else:
        stop = threading.Event()
        thread = threading.Thread(target=lambda: (sys.stdin.readline(), stop.set()), daemon=True)
        thread.start()
        asyncio.run(_run(args, stop, lambda: None))


if __name__ == "__main__":
    main()
