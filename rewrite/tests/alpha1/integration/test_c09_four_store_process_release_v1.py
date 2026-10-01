"""Real four-file rebase through separate PREPARED/SWITCHED/RELEASED processes.

Covers signed Owner source deletion, original history, surviving sources, old
file retirement and independent controlled-provider purge/reread. It excludes
privileged Linux administration and erasure at an external production provider.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def test_actual_owner_four_store_cold_rebase_and_release(tmp_path):
    support = Path(__file__).with_name("c09_four_store_process_acceptance_support_v1.py")
    environment = dict(os.environ)
    source_root = Path(__file__).resolve().parents[4]
    environment["PYTHONPATH"] = str(source_root) + os.pathsep + str(source_root / "rewrite") + os.pathsep + environment.get("PYTHONPATH", "")
    outcomes = []
    for phase, expected in (("prepare", "PREPARED"), ("switch", "SWITCHED"), ("release", "RELEASED"), ("verify", "RELEASED")):
        process = subprocess.run([sys.executable, str(support), phase, str(tmp_path)],
            capture_output=True, text=True, env=environment, timeout=180)
        assert process.returncode == 0, process.stderr
        outcome = json.loads(process.stdout.strip().splitlines()[-1])
        assert outcome["stage"] == expected
        assert outcome["generation"] == (1 if phase != "switch" else 1)
        outcomes.append(outcome)
    assert len({result["process_id"] for result in outcomes}) == len(outcomes)
    assert outcomes[-1]["fresh_owner_read"] and outcomes[-1]["fresh_owner_write"]
