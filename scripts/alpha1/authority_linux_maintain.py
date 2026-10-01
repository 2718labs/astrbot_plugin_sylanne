"""Run one existing signed package-maintenance operation as root.

Only the fixed bootstrap entry may launch this script. No package paths,
commands, credentials or backup DTOs are accepted from arguments.
"""
import argparse
import asyncio
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


async def run(operation):
    from sylanne3.authority_service.d12_package_supervisor_v2 import InstalledD12PackageSupervisorV2
    service=InstalledD12PackageSupervisorV2()
    try:return await service.run(operation)
    finally:service.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation',required=True)
    args=parser.parse_args()
    print(json.dumps(asyncio.run(run(args.operation)),sort_keys=True,separators=(',',':')))


if __name__=='__main__':main()
