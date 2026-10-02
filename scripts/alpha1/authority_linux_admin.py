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
    daemon, _ = open_linux_authority_v1(args.config)
    try:
        from sylanne3.authority_service.daemon import AuthorityFactualDaemonV2
        from sylanne3.authority_service.contract import AuthorityUnavailable
        if type(daemon) is AuthorityFactualDaemonV2:
            raise AuthorityUnavailable('C09 V2 factual-only installation: Owner mutation administration HOLD')
        return admin(rest, daemon=daemon)
    finally:
        asyncio.run(daemon.aclose())


if __name__ == "__main__":
    raise SystemExit(main())
