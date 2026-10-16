"""Run one permanent Alpha2 or Beta1 installed family once and retain its complete fixture.

Use an isolated Linux x86_64/glibc server environment. Product imports come
from the externally pinned extracted ZIP; tests come from its frozen source
companion. This tool does not install, issue grants, retry or repair data.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import platform
import sys
import zipfile

NUMERIC_FILE = "rewrite/tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py"
NODES = {
    "numeric-full": NUMERIC_FILE,
    "numeric-positive": NUMERIC_FILE + "::test_installed_life_numeric_original_paid_native_interval_and_trace",
    "numeric-authorization": NUMERIC_FILE + "::test_installed_life_numeric_egress_authorization_refusals",
    "numeric-registration": NUMERIC_FILE + "::test_installed_life_numeric_registration_replay_and_cancelled_job",
    "d13": "rewrite/tests/alpha1/integration/test_installed_d13_paid_v1.py",
    "c09-current": "rewrite/tests/alpha1/integration/test_c09_installed_life_archive_v1.py::test_installed_completed_life_segmented_four_role_current_v3",
    "sdk-real-elapsed": "rewrite/host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_a06_actual_installed_sdk_real_elapsed_day0_day4_day5_resume",
    "sdk-v7": "rewrite/host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_l03_actual_installed_sdk_d13_v7_256_current_core_count_paid_native_cold_replay",
}
FAMILIES = {
    "numeric-full": "numeric",
    "numeric-positive": "numeric_positive",
    "numeric-authorization": "numeric_authorization_groups",
    "numeric-registration": "numeric_registration",
    "d13": "d13_full",
    "c09-current": "c09_current",
    "sdk-v7": "sdk_d13_v7_256",
    "sdk-real-elapsed": "sdk_real_elapsed",
}
NATIVE_PATH = "rewrite/sylanne3/_native/linux-x86_64/libsylanne3_kernel.so"
NATIVE_SHA256 = "2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c"


def digest(body):
    return hashlib.sha256(body).hexdigest()


def pinned_file(path, pin):
    path = path.resolve(strict=True)
    body = path.read_bytes()
    if digest(body) != pin:
        raise ValueError(f"external SHA256 differs: {path}")
    return path, body


def relative_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value:
        raise ValueError("manifest contains a non-relative path")
    return path


def verify_rows(root, rows):
    names = set()
    for row in rows:
        relative = relative_path(row["path"])
        if row["path"] in names:
            raise ValueError("manifest repeats a file")
        names.add(row["path"])
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError(f"file leaves selected root: {relative}")
        body = path.read_bytes()
        if len(body) != row["bytes"] or digest(body) != row["sha256"]:
            raise ValueError(f"manifest file differs: {relative}")
    return names


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def require_beta1_snapshot(manifest, source_rows, package_bytes):
    """Check the exact new candidate pin before any application import."""
    snapshot = manifest["test_snapshot"]
    inventory = snapshot["engineering_source_inventory"]
    evidence = snapshot["verification_evidence"]
    qualification = manifest["backend_qualification"]
    if (package_bytes > 16_000_000 or manifest["candidate_scope"] != "beta1-server-test"
            or snapshot["schema"] != "sylanne.beta1-server-test-candidate.v1"
            or snapshot["public_release"] is not False
            or inventory["schema"] != "sylanne.engineering-source-inventory.v1"
            or digest(json.dumps(inventory["files"], ensure_ascii=True, sort_keys=True,
                separators=(",", ":")).encode()) != inventory["sha256"]
            or any(source_rows.get(row["path"]) != row for row in inventory["files"])
            or evidence["schema"] != "sylanne.beta1-source-evidence.v1"
            or digest(json.dumps(evidence, ensure_ascii=True, sort_keys=True,
                separators=(",", ":")).encode()) != snapshot["verification_evidence_digest"]
            or qualification["schema"] != "sylanne.beta1-server-test-qualification.v1"
            or qualification["runtime_scope"] != "backend-beta1-server-test"
            or snapshot["native_sha256"] != NATIVE_SHA256
            or snapshot["source_inventory_sha256"] != manifest["source_inventory"]["sha256"]):
        raise ValueError("Beta1 snapshot/source companion qualification differs")
    checks = evidence["checks"]
    by_name = {row["name"]: row for row in checks}
    if (len(by_name) != len(checks) or any(row["source_pin"] != inventory["sha256"] for row in checks)
            or any(name not in by_name or by_name[name]["status"] != "passed"
                for name in ("beta1_source_closure", "beta1_python_compile"))
            or "beta1_server_acceptance" not in by_name
            or by_name["beta1_server_acceptance"]["status"] != "not_run"):
        raise ValueError("Beta1 needs fresh pinned local receipts and server NOT_RUN")


def run(args):
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"} or platform.libc_ver()[0] != "glibc":
        raise RuntimeError("requires isolated Linux x86_64/glibc")
    package, _ = pinned_file(args.package, args.package_sha256)
    installed = args.installed_root.resolve(strict=True)
    source = args.source_root.resolve(strict=True)
    source_manifest, source_raw = pinned_file(args.source_manifest, args.source_manifest_sha256)
    source_document = json.loads(source_raw)
    if source_document["schema"] != "sylanne.local-source-freeze.v1":
        raise ValueError("requires a frozen source companion manifest")
    source_names = verify_rows(source, source_document["files"])
    source_rows = {row["path"]: row for row in source_document["files"]}
    runner_relative = "scripts/alpha1/verify_server_installation.py"
    if runner_relative not in source_names or Path(__file__).resolve() != source / runner_relative:
        raise ValueError("run the verifier from the exact frozen source companion")
    with zipfile.ZipFile(package) as archive:
        if archive.testzip() is not None:
            raise ValueError("package CRC verification failed")
        manifest_raw = archive.read("release-manifest.json")
        if digest(manifest_raw) != args.manifest_sha256:
            raise ValueError("external release-manifest SHA256 differs")
        manifest = json.loads(manifest_raw)
        identity = (manifest["package_version"], manifest["build_mode"])
        if identity not in {("3.0.0-alpha2", "alpha2-candidate"),
                            ("3.0.0-beta1", "beta1-candidate")} or tuple(
                manifest["platform"][name] for name in ("os", "arch", "libc", "abi_version")) != (
                    "linux", "x86_64", "glibc", 2):
            raise ValueError("requires an exact Alpha2 or Beta1 Linux x86_64/glibc ABI2 candidate")
        if identity == ("3.0.0-beta1", "beta1-candidate"):
            require_beta1_snapshot(manifest, source_rows, package.stat().st_size)
        run_schema = ("sylanne.beta1-server-single-run.v1" if identity[0] == "3.0.0-beta1"
                      else "sylanne.alpha2-server-single-run.v1")
        listed = verify_rows(installed, manifest["files"])
        members = archive.namelist()
        if len(members) != len(set(members)) or set(members) != listed | {"release-manifest.json"}:
            raise ValueError("package member set differs from manifest")
        for row in manifest["files"]:
            if row["path"] != NATIVE_PATH and source_rows.get(row["path"]) != row:
                raise ValueError("package and engineering source are different snapshots")
            body = archive.read(row["path"])
            if len(body) != row["bytes"] or digest(body) != row["sha256"]:
                raise ValueError("archive file differs from manifest")
    if (installed / "release-manifest.json").read_bytes() != manifest_raw:
        raise ValueError("extracted release manifest differs from ZIP")
    native = manifest["native"]
    if native != {"path": NATIVE_PATH, "bytes": 596248, "sha256": NATIVE_SHA256}:
        raise ValueError("unchanged pinned native original required")
    node = NODES[args.node]
    if node.partition("::")[0] not in source_names:
        raise ValueError("selected node is absent from frozen source")
    input_paths, input_pins = {}, {}
    for path, pin, label in (
        (args.dependency_manifest, args.dependency_manifest_sha256, "dependency_manifest"),
        (args.approved_install_request, args.approved_install_request_sha256, "approved_install_request")):
        if path is None or pin is None:
            raise ValueError("externally pinned dependencies and an approved initial request are required")
        checked, body = pinned_file(path, pin)
        input_paths[label] = str(checked)
        input_pins[label + "_sha256"] = digest(body)
    if args.delivery_root is None or args.fixture_root is None or args.cgroup_parent is None:
        raise ValueError("explicit delivery/fixture roots and the real delegated cgroup parent are required")
    if args.node not in {"sdk-v7", "sdk-real-elapsed"} and args.installed_stage_root is None:
        raise ValueError("explicit separately verified installed-stage root is required")
    beta1_suite=identity==("3.0.0-beta1","beta1-candidate") and args.node in {"numeric-full","d13"}
    if identity==("3.0.0-beta1","beta1-candidate") and args.node in {
            "numeric-positive","numeric-authorization","numeric-registration"}:
        raise ValueError("Beta1 Numeric requires its complete ten-node protected phase suite; subset fallback HOLD")
    setup = setup_pin = None
    setup_values = (args.phase_fixture_setup, args.phase_fixture_setup_sha256, args.phase_setup_root, args.engineering_inventory_sha256)
    if args.node == "c09-current" or beta1_suite:
        if any(value is None for value in setup_values):
            raise ValueError("current C09/Beta1 full suite requires fresh protected setup and frozen engineering inventory pins")
        setup, setup_raw = pinned_file(args.phase_fixture_setup, args.phase_fixture_setup_sha256)
        setup_pin = digest(setup_raw)
        inventory = json.loads((source.parent / "frozen-engineering-inventory.json").read_bytes())
        inventory_digest = digest(json.dumps(inventory["files"], sort_keys=True, separators=(",", ":")).encode())
        if (inventory["schema"] != "sylanne.engineering-source-inventory.v1"
                or inventory["sha256"] != inventory_digest or inventory_digest != args.engineering_inventory_sha256):
            raise ValueError("external frozen canonical engineering inventory pin differs")
        if any(source_rows.get(row["path"]) != row for row in inventory["files"]):
            raise ValueError("engineering inventory differs from the frozen source companion")
    elif any(value is not None for value in setup_values):
        raise ValueError("protected phase setup applies to current C09 or the full Beta1 Numeric/D13 suite")
    phase_root = phase_approval = phase_approval_pin = None
    phase_values = (args.phase, args.phase_root, args.phase_approval, args.phase_approval_sha256)
    if args.node == "sdk-real-elapsed":
        if any(value is None for value in phase_values):
            raise ValueError("real-elapsed phase, persistent root and external initial approval pin required")
        phase_root = args.phase_root.resolve()
        phase_approval, raw_approval = pinned_file(args.phase_approval, args.phase_approval_sha256)
        phase_approval_pin = digest(raw_approval)
        if phase_root.is_relative_to(source) or phase_root.is_relative_to(installed):
            raise ValueError("persistent phase data must be separate from source and installed code")
    elif any(value is not None for value in phase_values):
        raise ValueError("phase arguments apply only to sdk-real-elapsed")
    output = args.output_dir.resolve()
    if any(output.is_relative_to(path) for path in (source, installed)):
        raise ValueError("receipts must be separate from source and installed code")
    if phase_root is not None and (phase_root.is_relative_to(output) or output.is_relative_to(phase_root)):
        raise ValueError("real-elapsed persistent root and fresh run receipts must be separate")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    packet = {"schema": run_schema, "node": node,
        "installed_root": str(installed), "source_root": str(source),
        "package": str(package), "package_sha256": args.package_sha256,
        "manifest_sha256": args.manifest_sha256, "source_manifest": str(source_manifest),
        "source_manifest_sha256": args.source_manifest_sha256,
        "native_sha256": NATIVE_SHA256, "input_pins": input_pins, "input_paths": input_paths,
        "phase_fixture_setup": str(setup) if setup is not None else None,
        "phase_fixture_setup_sha256": setup_pin,
        "engineering_inventory_sha256": args.engineering_inventory_sha256,
        "real_elapsed_phase": args.phase, "real_elapsed_directory": str(phase_root) if phase_root is not None else None,
        "real_elapsed_approval_sha256": phase_approval_pin,
        "fixture": str(output / "fixture"),
        "started_utc": datetime.now(timezone.utc).isoformat(), "old_pass_transfer": False}
    write_json(output / "run-input.json", packet)
    # One stdlib-only observer creates and verifies its app before the fixed
    # child can import any SDK/product code. Every CLI uses this same path.
    from uuid import uuid4
    sys.path.insert(0, str(source))
    from rewrite.host_tests.alpha1.owned_resource_profile_v1 import (
        FIXTURE_NODES, PHASE_FIXTURE_KINDS, OwnedResourceRunV1, run_owned_resource_profile_v1)
    family = FAMILIES[args.node]
    selected = FIXTURE_NODES[family]
    spec = OwnedResourceRunV1(
        fixture_kind=family, operation_id=str(uuid4()),
        package_path=str(package), package_sha256=args.package_sha256,
        manifest_sha256=args.manifest_sha256, frozen_rewrite_root=str(source / "rewrite"),
        helper_sha256=source_rows["rewrite/" + selected[0].partition("::")[0]]["sha256"],
        dependency_manifest=input_paths["dependency_manifest"],
        dependency_sha256=args.dependency_manifest_sha256,
        approved_install_request=input_paths["approved_install_request"],
        request_sha256=args.approved_install_request_sha256,
        basetemp=packet["fixture"], evidence_directory=str(output / "resource"),
        installed_root=str(installed),
        delivery_root=str(args.delivery_root.resolve(strict=True)),
        fixture_root=str(args.fixture_root.resolve(strict=True)),
        installed_stage_root=(str(args.installed_stage_root.resolve(strict=True))
                              if args.installed_stage_root is not None else None),
        sdk_root=str(args.sdk_root.resolve(strict=True)) if args.sdk_root is not None else None,
        phase_fixture_setup=str(setup) if setup is not None else None,
        phase_fixture_setup_sha256=setup_pin,
        phase_setup_root=str(args.phase_setup_root.resolve(strict=True)) if args.phase_setup_root is not None else None,
        engineering_inventory_sha256=args.engineering_inventory_sha256,
        real_elapsed_phase=args.phase,
        real_elapsed_directory=str(phase_root) if phase_root is not None else None,
        real_elapsed_approval=str(phase_approval) if phase_approval is not None else None,
        real_elapsed_approval_sha256=phase_approval_pin)
    summary = run_owned_resource_profile_v1(spec,
        cgroup_parent=str(args.cgroup_parent.resolve(strict=True)), timeout_seconds=1000)
    if beta1_suite:
        outcomes_path=output/"resource/actualphase-outcomes.json"
        outcomes=json.loads(outcomes_path.read_bytes())if outcomes_path.is_file()else None
        scope_executed=(outcomes is not None and outcomes["schema"]=="sylanne.beta1.actualphase-outcomes.v3"
            and outcomes["harness_kind"]=="root_controlled_beta1_suite"
            and outcomes["fixture_kind"]==family and outcomes["suite_sha256"]==setup_pin
            and outcomes["operation_id"]==spec.operation_id
            and outcomes["package_sha256"]==spec.package_sha256 and outcomes["manifest_sha256"]==spec.manifest_sha256
            and outcomes["full_manifest_node_count"]==len(outcomes["node_manifest"])==15
            and outcomes["requested_node_count"]==len(selected)
            and outcomes["observation_status"]=="CURRENT_FAMILY_OBSERVED_OTHER_FAMILY_NOT_RUN"
            and outcomes["node_count"]==len(outcomes["node_outcomes"])==len(selected)
            and tuple(item["node"]for item in outcomes["node_outcomes"])==selected
            and outcomes["effective_exit_code"]==0
            and all(len(item["outcomes"])==len(item["processes"])==5 and item["checks"]
                and all(item["checks"].values())for item in outcomes["node_outcomes"])
            and summary.get("actual_phase_outcomes_path")==str(outcomes_path)
            and all(row["status"]==("OBSERVED_CURRENT_V3_EXIT"if row["fixture_kind"]==family else"NOT_RUN")for row in outcomes["node_manifest"]))
    elif family == "c09_current":
        outcomes_path=output/"resource/actualphase-outcomes.json"
        outcomes=json.loads(outcomes_path.read_bytes())if outcomes_path.is_file()else None
        scope_executed=(outcomes is not None and outcomes["schema"]=="sylanne.actualphase-outcomes.v3"
            and outcomes["harness_kind"]=="root_controlled_four_phase" and outcomes["node"]==selected[0]
            and outcomes["node_sha256"]==spec.helper_sha256 and outcomes["operation_id"]==spec.operation_id
            and outcomes["package_sha256"]==spec.package_sha256 and outcomes["manifest_sha256"]==spec.manifest_sha256
            and outcomes["effective_exit_code"]==0 and len(outcomes["processes"])==4 and all(outcomes["checks"].values())
            and summary.get("actual_phase_outcomes_path")==str(outcomes_path))
    else:
        outcomes_path=(output/"fixture/evidence"if family in PHASE_FIXTURE_KINDS else output/"resource")/"pytest-outcomes.json"
        outcomes=json.loads(outcomes_path.read_bytes())if outcomes_path.is_file()else None
        scope_executed=(summary.get("pytest_outcomes_path")==str(outcomes_path)and outcomes is not None
            and outcomes["effective_exit_code"]==0 and outcomes["collected"]==len(selected))
    qualified = (summary["status"] == "FIXTURE_EXIT_OBSERVED_NOT_QUALIFICATION"
        and summary.get("actual_exit") == 0 and summary.get("owned_groups_removed") is True
        and summary.get("recursive_populated_after_cleanup") == "0"
        and summary.get("original_pidfd_ready_after_cleanup") is True
        and summary.get("added_tokens_restored") is not False
        and "cleanup_failure" not in summary and scope_executed)
    receipt = {"schema": packet["schema"], "status": "PASS" if qualified else "HOLD",
        "node": node, "selector": family, "expected_instances": len(selected),
        "real_elapsed_phase": args.phase, "real_elapsed_directory": str(phase_root) if phase_root is not None else None,
        "exact_nodes": ["rewrite/" + value for value in selected],
        "exit_code": 0 if qualified else 2,
        "package_sha256": args.package_sha256, "manifest_sha256": args.manifest_sha256,
        "source_manifest_sha256": args.source_manifest_sha256,
        "resource_original": str(output / "resource/resource-run-original.json"),
        "harness_kind": ("root_controlled_beta1_suite" if beta1_suite else
            "root_controlled_four_phase" if family=="c09_current" else "pytest"),
        "actual_phase_outcomes" if beta1_suite or family=="c09_current" else "pytest_outcomes": str(outcomes_path),
        "scope": "selected isolated fixture and owned resource subtree; no all39/production acceptance",
        **({"full_manifest_node_count":15,"node_manifest_observations":None if outcomes is None else outcomes["node_manifest"],
            "unobserved_state":"UNKNOWN"if outcomes is None else outcomes["observation_status"],
            "committed_active_core_finish_ack_loss":"NOT_RUN"}if beta1_suite else{})}
    write_json(output / "run-result.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False))
    return receipt["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-nodes", action="store_true")
    parser.add_argument("--phase", choices=("day0", "day4", "day5"))
    parser.add_argument("--node", choices=tuple(NODES))
    for name in ("package", "installed-root", "source-root", "source-manifest", "output-dir",
                 "dependency-manifest", "approved-install-request", "delivery-root", "fixture-root", "installed-stage-root", "sdk-root", "cgroup-parent", "phase-root", "phase-approval", "phase-fixture-setup", "phase-setup-root"):
        parser.add_argument("--" + name, type=Path)
    for name in ("package-sha256", "manifest-sha256", "source-manifest-sha256",
                 "dependency-manifest-sha256", "approved-install-request-sha256", "phase-approval-sha256", "phase-fixture-setup-sha256", "engineering-inventory-sha256"):
        parser.add_argument("--" + name)
    args = parser.parse_args()
    if args.list_nodes:
        print(json.dumps(NODES, ensure_ascii=False, indent=2))
        return 0
    required = (args.node, args.package, args.package_sha256, args.manifest_sha256,
        args.installed_root, args.source_root, args.source_manifest, args.source_manifest_sha256, args.output_dir)
    if any(value is None for value in required):
        parser.error("one node, package/extracted root/source companion, external pins and a new output directory are required")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
