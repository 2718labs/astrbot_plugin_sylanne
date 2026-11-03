"""Run the independently installed Owner maintenance console."""
from __future__ import annotations

import argparse
from pathlib import Path

from .authority_service.maintenance_console_deployment_v1 import build_linux_maintenance_console_v1
from .diagnostic_channel_v1 import StderrDiagnosticSinkV1, install_diagnostic_sink_v1


def main():
    # Independent trusted-service process: stderr is its formal service log.
    install_diagnostic_sink_v1(StderrDiagnosticSinkV1(), replace=False)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",type=Path,required=True,help="absolute protected maintenance-console client configuration")
    args=parser.parse_args()
    server=build_linux_maintenance_console_v1(client_config_path=args.config)
    server.run_v1()


if __name__=="__main__":
    main()
