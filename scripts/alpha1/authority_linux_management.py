"""Explicit offline Linux installation-management administration."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("initialize", "grant", "revoke"))
    parser.add_argument("--config", type=Path, default=Path("/etc/sylanne/authority/deployment.json"))
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--installation-id", required=True)
    parser.add_argument("--initial-enabled", choices=("true", "false"))
    parser.add_argument("--principal", type=Path, help="Public registered Owner principal JSON; no private key")
    parser.add_argument("--permission", action="append", default=[], choices=(
        "installation.logs.read", "installation.settings.read", "installation.settings.enabled.write"))
    parser.add_argument("--valid-until-utc")
    args = parser.parse_args()
    from sylanne3.authority_service.installation_management_admin_v1 import (
        InstallationManagementAdminCommandV1, execute_installation_management_admin_v1,
    )
    from sylanne3.authority_service.linux_deployment_v1 import open_linux_authority_v1
    from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
    principal = None
    if args.principal is not None:
        data = args.principal.read_bytes()
        if len(data) > 4096:
            raise ValueError("public principal exceeds its bound")
        principal = OwnerPrincipalV1(**json.loads(data))
    command = InstallationManagementAdminCommandV1(args.action, args.namespace,
        args.profile_id, args.installation_id,
        None if args.initial_enabled is None else args.initial_enabled == "true",
        principal, tuple(args.permission),
        None if args.valid_until_utc is None else datetime.fromisoformat(args.valid_until_utc.replace("Z", "+00:00")))
    bootstrap, _ = open_linux_authority_v1(args.config)
    async def run_offline():
        try:
            daemon=await bootstrap.await_offline_ready_v3()
            result=execute_installation_management_admin_v1(daemon,command)
            print(json.dumps(result,sort_keys=True))
        finally:
            await bootstrap.aclose()
    asyncio.run(run_offline())


if __name__ == "__main__":
    main()
