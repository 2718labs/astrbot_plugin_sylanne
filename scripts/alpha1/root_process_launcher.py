"""Fixed installed private-namespace PID1 launcher, never a shell server."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('installed_entry',choices=('legacy-v2','lifetime-v3'))
    args=parser.parse_args()
    from sylanne3.authority_service.installed_process_supervisor_v1 import RootProcessLauncherV1
    launcher = RootProcessLauncherV1(
        host_spec_path="/etc/sylanne/supervision/host.json",
        authority_spec_path="/etc/sylanne/supervision/authority.json")
    if args.installed_entry=='lifetime-v3':
        from sylanne3.authority_service.installed_root_lifetime_observer_v3 import require_installed_root_lifetime_v3
        require_installed_root_lifetime_v3(launcher.specs['host'],launcher.specs['authority'])
    raise SystemExit(launcher.serve_forever_v1())


if __name__ == "__main__":
    main()
