"""Offline Linux Owner administration using the protected installed registry."""
from __future__ import annotations
import argparse
import asyncio
from pathlib import Path
import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--config", type=Path, default=Path("/etc/sylanne/authority/deployment.json"))
    args, rest = parser.parse_known_args()
    from sylanne3.authority_service.linux_deployment_v1 import open_linux_authority_v1
    from sylanne3.authority_service.admin_cli import main as admin
    bootstrap, _ = open_linux_authority_v1(args.config)
    async def run_offline():
        try:
            daemon=await bootstrap.await_offline_ready_v3()
            return admin(rest,daemon=daemon)
        finally:
            await bootstrap.aclose()
    return asyncio.run(run_offline())


if __name__ == "__main__":
    raise SystemExit(main())
