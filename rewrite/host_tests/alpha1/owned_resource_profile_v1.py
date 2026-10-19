"""One-shot resource envelope for fixed qualification families, never a root shell.

The external observer is stdlib-only. The fresh child self-places before any
package/SDK work, waits for independently verified membership, then execs the
fixed permanent pytest nodes. This limits the actual fixture subtree, not the whole machine.
"""
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
import traceback
from uuid import UUID


PYTHON = sys.executable
NODE = "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_b04_actual_installed_sdk_owner_management_d05_quit_restart"


class FixtureKind(StrEnum):
    B04 = "b04"
    B04_PROBE_DIAGNOSTIC = "b04_probe_diagnostic"
    NUMERIC = "numeric"
    NUMERIC_POSITIVE = "numeric_positive"
    NUMERIC_AUTHORIZATION_GROUPS = "numeric_authorization_groups"
    NUMERIC_REGISTRATION = "numeric_registration"
    NUMERIC_PREPARATION = "numeric_preparation"
    NUMERIC_AUTHORIZATION = "numeric_authorization"
    NUMERIC_WORKER_TIME = "numeric_worker_time"
    NUMERIC_STAGE_MUTATION = "numeric_stage_mutation"
    NUMERIC_DIAGNOSTIC = "numeric_diagnostic"
    NUMERIC_NATIVE_WAIT_DIAGNOSTIC = "numeric_native_wait_diagnostic"
    D13 = "d13"
    D13_FULL = "d13_full"
    C09_CURRENT = "c09_current"
    D13_V6 = "d13_v6"
    M1 = "m1"
    M1_PHASE_FULL = "m1_phase_full"
    M1_PHASE_REVISION = "m1_phase_revision"
    M1_PHASE_OWNER_READ = "m1_phase_owner_read"
    M1_PHASE_PAUSE_PREPARED = "m1_phase_pause_prepared"
    M1_PHASE_PAUSE_UNKNOWN = "m1_phase_pause_unknown"
    M1_PHASE_D05_RICH = "m1_phase_d05_rich"
    M1_PHASE_METHOD_PREREQUISITES = "m1_phase_method_prerequisites"
    M1_PHASE_METHOD_COMPARISON = "m1_phase_method_comparison"
    CONTACT_P2_SERIAL = "contact_p2_serial"
    M1_OWNER_SOURCE_NOTE_FULL = "m1_owner_source_note_full"
    M1_OWNER_SOURCE_NOTE_CANCEL = "m1_owner_source_note_cancel"
    M1_OWNER_SOURCE_NOTE_UNKNOWN = "m1_owner_source_note_unknown"
    M1_OWNER_SOURCE_NOTE_FAILED = "m1_owner_source_note_failed"
    INSTALLED_L02_C3_RESTART = "installed_l02_c3_restart"
    INSTALLED_L02_OFFLINE_RESTART = "installed_l02_offline_restart"
    SDK_M1 = "sdk_m1"
    SDK_ORDINARY_RECALL = "sdk_ordinary_recall"
    SDK_GREETING = "sdk_greeting"
    SDK_D13_V6_256 = "sdk_d13_v6_256"
    SDK_D13_V7_256 = "sdk_d13_v7_256"
    SDK_REAL_ELAPSED = "sdk_real_elapsed"
    SDK_M1_NATURAL_STOP = "sdk_m1_natural_stop"
    SDK_M1_NATURAL_UNKNOWN = "sdk_m1_natural_unknown"


FIXTURE_NODES = {
    "b04": (NODE,),
    "c09_current": ("tests/alpha1/integration/test_c09_installed_life_archive_v1.py::test_installed_completed_life_segmented_four_role_current_v3",),
    "b04_probe_diagnostic": (NODE,),
    "sdk_m1": ("host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_m1_actual_installed_sdk_two_message_task_and_reply_chain",),
    "numeric_native_wait_diagnostic": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_native_post_terminal_wait_probe",),
    "numeric_diagnostic": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_first_decision_time_probe",),
    "numeric_stage_mutation": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[prepare]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[acquire]"),
    "numeric_worker_time": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[worker]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[time]"),
    "numeric_authorization": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_registration_replay_and_cancelled_job",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[installation]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[lease]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[reservation]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[configuration]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[worker]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[time]"),
    "numeric_preparation": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_registration_replay_and_cancelled_job",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[prepare]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[acquire]"),
    "numeric": (
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_original_paid_native_interval_and_trace",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_registration_replay_and_cancelled_job",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[prepare]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_stage_original_mutation_refused[acquire]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[installation]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[lease]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[reservation]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[configuration]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[worker]",
        "tests/alpha1/integration/test_installed_life_numeric_fullchain_v1.py::test_installed_life_numeric_egress_authorization_refusals[time]"),
    "d13": (
        "tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_paid_standby_current_cold_and_no_charge_replay",
        "tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_paid_expired_original_never_calls_provider",
        "tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_paid_authorized_ceiling_reaches_admission"),
    "d13_v6": (
        "tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_v6_paid_derived_current_cold_and_no_charge_replay",
        "tests/alpha1/integration/test_installed_d13_paid_v1.py::test_installed_d13_v6_derived_expiry_reclaims_only_named_payload_and_recovers_lost_ack"),
    "m1": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_m1_actual_c4_billing_content_and_draft_pipeline",
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_m1_stop_between_actual_observation_and_final_core",
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_m1_invalid_billing_keeps_unknown_money_and_no_authored_adoption"),
    "m1_phase_full": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_phase_st0_actual_full_generation_file_readback_v2",),
    "m1_phase_revision": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_phase_st0_two_observed_messages_same_file_goal_v2",),
}
# CLI-specific scopes preserve the existing broader family meanings.
FIXTURE_NODES.update({
    "numeric_positive": FIXTURE_NODES["numeric"][:1],
    "numeric_authorization_groups": FIXTURE_NODES["numeric_authorization"][1:],
    "numeric_registration": FIXTURE_NODES["numeric_authorization"][:1],
    "d13_full": FIXTURE_NODES["d13"] + FIXTURE_NODES["d13_v6"],
})

FIXTURE_NODES.update({
    "sdk_real_elapsed": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_a06_actual_installed_sdk_real_elapsed_day0_day4_day5_resume",),
    "sdk_d13_v7_256": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_l03_actual_installed_sdk_d13_v7_256_current_core_count_paid_native_cold_replay",),
    "m1_owner_source_note_full": (
        "tests/alpha1/integration/test_installed_owner_source_note_task_v1.py::test_installed_owner_source_note_public_material_full_self_task_v1",),
    "m1_owner_source_note_cancel": (
        "tests/alpha1/integration/test_installed_owner_source_note_task_v1.py::test_installed_owner_source_note_cancel_preserves_original_and_rejects_old_worker_v1",),
    "m1_owner_source_note_unknown": (
        "tests/alpha1/integration/test_installed_owner_source_note_task_v1.py::test_installed_owner_source_note_native_lost_ack_recovers_same_original_once_v1",),
    "m1_owner_source_note_failed": (
        "tests/alpha1/integration/test_installed_owner_source_note_task_v1.py::test_installed_owner_source_note_artifact_io_failure_keeps_actual_cpu_once_v1",),
    "installed_l02_c3_restart": (
        "tests/alpha1/integration/test_installed_l02_process_restart_v1.py::test_installed_l02_c3_waiting_process_restart_wakes_once",),
    "installed_l02_offline_restart": (
        "tests/alpha1/integration/test_installed_l02_process_restart_v1.py::test_installed_l02_offline_restart_tick_original_once",),
})
FIXTURE_NODES.update({
    "m1_phase_method_comparison": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_method_trial_sample_full_pair_measurement_unknown_benefit_v2",),
    "contact_p2_serial": (
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_actual_sdk_accepted_once",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_actual_sdk_unknown_keeps_original_no_resend",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_foreign_current_capsule_denies_before_sdk",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_current_gate_denies_before_sdk[revoke]",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_current_gate_denies_before_sdk[silent]",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_current_gate_denies_before_sdk[boundary]",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_current_gate_denies_before_sdk[expired]",
        "tests/alpha1/integration/test_installed_contact_sender_v3.py::test_installed_contact_p2_unknown_unanswered_blocks_actual_new_parent",
    ),
    "m1_phase_method_prerequisites": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_method_v4_current_task_no_search_and_missing_gp1_hold",),
    "m1_phase_d05_rich": (
        "tests/alpha1/integration/test_current_domain_production_v1.py::test_installed_relationship_authored_prior_and_actual_shared_c3_revision_v2",),
    "m1_phase_owner_read": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_phase_owner_artifact_read_current_identity_source_and_file_v2",
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_owner_artifact_named_body_wire_bound_only_v2"),
    "m1_phase_pause_prepared": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_phase_owner_pause_blocks_prepared_and_new_work_v2",),
    "m1_phase_pause_unknown": (
        "tests/alpha1/integration/test_m1_installed_artifact_draft_v1.py::test_installed_phase_owner_pause_preserves_actual_unknown_and_resume_hold_v2",),
})
PHASE_FIXTURE_KINDS = frozenset({"c09_current", "m1_phase_full", "m1_phase_revision",
    "m1_phase_owner_read", "m1_phase_pause_prepared", "m1_phase_pause_unknown", "m1_phase_d05_rich", "m1_phase_method_prerequisites", "m1_phase_method_comparison",
    "m1_owner_source_note_full", "m1_owner_source_note_cancel", "m1_owner_source_note_unknown", "m1_owner_source_note_failed",
    "installed_l02_c3_restart", "installed_l02_offline_restart"})
L02_FIXTURE_KINDS = frozenset({"installed_l02_c3_restart", "installed_l02_offline_restart"})
SDK_M1_KINDS = frozenset({"sdk_m1", "sdk_m1_natural_stop", "sdk_m1_natural_unknown", "sdk_ordinary_recall", "sdk_greeting", "sdk_d13_v6_256", "sdk_d13_v7_256", "sdk_real_elapsed"})
FIXTURE_NODES.update({
    "sdk_d13_v6_256": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_l03_actual_installed_sdk_d13_v6_256_current_paid_native_cold_replay_expiry",),
    "sdk_greeting": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_a02_actual_installed_sdk_greeting_adopted_no_search_zero_c3_c04",),
    "sdk_ordinary_recall": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_a02_actual_installed_sdk_ordinary_related_old_source_recall_and_reply",),
    "sdk_m1_natural_stop": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_m1_actual_installed_sdk_first_bubble_stop_preserves_effect_and_core_roster",),
    "sdk_m1_natural_unknown": (
        "host_tests/alpha1/test_b04_installed_lifecycle_v1.py::test_m1_actual_installed_sdk_first_bubble_unknown_holds_remaining_and_parent_fees_once",),
})
PACKAGE_NAMES = frozenset({
    "astrbot_plugin_sylanne-3.0.0-alpha1-linux-x86_64-glibc-alpha1-test-snapshot.zip",
    "astrbot_plugin_sylanne-3.0.0-alpha2-linux-x86_64-glibc-alpha2-candidate.zip",
    "astrbot_plugin_sylanne-3.0.0-beta1-linux-x86_64-glibc-beta1-candidate.zip",
})
LOG_LIMIT = 8 * 1024 * 1024
PAGE_BYTES = os.sysconf("SC_PAGE_SIZE")
RUN_MEMORY_BUDGET_BYTES = 2_000_000_000
RUN_CONTROLS = {"cpu.max": "200000 100000",
                "memory.max": str(RUN_MEMORY_BUDGET_BYTES // PAGE_BYTES * PAGE_BYTES),
                "memory.swap.max": "0", "memory.oom.group": "1"}
APP_CONTROLS = {"memory.max": "1342177280", "memory.high": "1073741824",
                "memory.swap.max": "0", "memory.oom.group": "1"}
METRICS = ("cgroup.events", "memory.current", "memory.peak", "memory.events",
           "memory.events.local", "memory.stat", "memory.swap.current", "memory.swap.events",
           "cpu.stat", "cpu.pressure", "memory.pressure")


BETA1_CURRENT_SUITE_KINDS=frozenset({"numeric","numeric_positive","numeric_authorization_groups","numeric_registration","d13_full"})
BETA1_PACKAGE_NAME="astrbot_plugin_sylanne-3.0.0-beta1-linux-x86_64-glibc-beta1-candidate.zip"


def _uses_beta1_current_suite_v3(spec):
    return Path(spec.package_path).name==BETA1_PACKAGE_NAME and spec.fixture_kind in BETA1_CURRENT_SUITE_KINDS


def _validate_phase_fixture_setup(path_value, expected_sha256, setup_root):
    setup_root = Path(setup_root)
    path = Path(path_value)
    if (not path.is_relative_to(setup_root)
            or path.parent == path or path == setup_root):
        raise ValueError("Root-owned protected phase fixture setup path required")
    if path.resolve(strict=True) != path:
        raise ValueError("canonical phase fixture setup path required")
    directory = path.parent
    while True:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError("root-owned protected phase fixture setup ancestry required")
        if directory == setup_root:
            break
        directory = directory.parent
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o644):
        raise ValueError("root-owned mode-0644 regular phase fixture setup required")
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256:
        raise ValueError("phase fixture setup bytes changed from the supplied pin")


def _validate_c09_engineering_inventory_v1(spec):
    inventory_path = Path(spec.frozen_rewrite_root).parent.parent / "frozen-engineering-inventory.json"
    inventory = json.loads(inventory_path.read_bytes())
    actual = sha256(json.dumps(inventory["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (inventory["schema"] != "sylanne.engineering-source-inventory.v1"
            or inventory["sha256"] != actual or spec.engineering_inventory_sha256 != actual):
        raise ValueError("externally pinned current C09 engineering inventory required")


@dataclass(frozen=True)
class OwnedResourceRunV1:
    fixture_kind: str
    operation_id: str
    package_path: str
    package_sha256: str
    manifest_sha256: str
    frozen_rewrite_root: str
    helper_sha256: str
    dependency_manifest: str
    dependency_sha256: str
    approved_install_request: str
    request_sha256: str
    basetemp: str
    evidence_directory: str
    installed_root: str | None = None
    phase_fixture_setup: str | None = field(default=None, kw_only=True)
    phase_fixture_setup_sha256: str | None = field(default=None, kw_only=True)
    delivery_root: str | None = field(default=None, kw_only=True)
    fixture_root: str | None = field(default=None, kw_only=True)
    installed_stage_root: str | None = field(default=None, kw_only=True)
    sdk_root: str | None = field(default=None, kw_only=True)
    phase_setup_root: str | None = field(default=None, kw_only=True)
    engineering_inventory_sha256: str | None = field(default=None, kw_only=True)
    real_elapsed_phase: str | None = field(default=None, kw_only=True)
    real_elapsed_directory: str | None = field(default=None, kw_only=True)
    real_elapsed_approval: str | None = field(default=None, kw_only=True)
    real_elapsed_approval_sha256: str | None = field(default=None, kw_only=True)

    def __post_init__(self):
        # Explicit server roots are persisted in the frozen spec sent to the
        # child. Environment values are resolved once here, never in the child.
        for name in ("delivery_root", "fixture_root", "installed_stage_root", "phase_setup_root"):
            value = getattr(self, name) or os.environ.get("SYLANNE_QUAL_" + name.upper())
            required = name in {"delivery_root", "fixture_root"} or (
                name == "installed_stage_root" and self.fixture_kind != "b04"
                and self.fixture_kind not in SDK_M1_KINDS) or (
                name == "phase_setup_root" and (self.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(self)))
            if required and value is None:
                raise ValueError("explicit server " + name + " required")
            if value is not None:
                path = Path(value)
                if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
                    raise ValueError("canonical existing server " + name + " required")
                object.__setattr__(self, name, str(path))
        dependency_raw = Path(self.dependency_manifest).read_bytes()
        if sha256(dependency_raw).hexdigest() != self.dependency_sha256:
            raise ValueError("external dependency manifest pin differs")
        dependency = json.loads(dependency_raw)
        if dependency["sdk_version"] != "4.28.2" or dependency["python_version"] != "3.12.3":
            raise ValueError("actual pinned AstrBot4.28.2/Python3.12.3 dependency profile required")
        sdk = self.sdk_root or os.environ.get("SYLANNE_QUAL_SDK_ROOT") or dependency["official_sdk_source"]
        sdk = Path(sdk)
        if (not sdk.is_absolute() or sdk.resolve(strict=True) != sdk or not sdk.is_dir()
                or str(sdk) != dependency["official_sdk_source"]):
            raise ValueError("SDK root differs from externally pinned actual dependency manifest")
        object.__setattr__(self, "sdk_root", str(sdk))
        phase_inputs = (self.real_elapsed_phase, self.real_elapsed_directory,
                        self.real_elapsed_approval, self.real_elapsed_approval_sha256)
        if self.fixture_kind == "sdk_real_elapsed":
            if (self.real_elapsed_phase not in {"day0", "day4", "day5"}
                    or any(value is None for value in phase_inputs)):
                raise ValueError("real-elapsed phase, persistent root and external approval pin required")
            persistent = Path(self.real_elapsed_directory)
            if not persistent.is_absolute() or persistent.resolve() != persistent:
                raise ValueError("canonical explicit persistent real-elapsed root required")
            if persistent.exists() and (not persistent.is_dir() or persistent.stat().st_uid != 0
                                        or stat.S_IMODE(persistent.stat().st_mode) != 0o700):
                raise ValueError("existing real-elapsed root must remain Root-private mode0700")
            if self.real_elapsed_phase != "day0" and not persistent.is_dir():
                raise ValueError("resumed phase requires its existing persistent root")
            approval = Path(self.real_elapsed_approval)
            if approval.resolve(strict=True) != approval or sha256(approval.read_bytes()).hexdigest() != self.real_elapsed_approval_sha256:
                raise ValueError("real-elapsed initial approval differs from external pin")
            if any(persistent.is_relative_to(Path(value)) or Path(value).is_relative_to(persistent)
                   for value in (self.basetemp, self.evidence_directory)):
                raise ValueError("persistent real-elapsed data must be separate from disposable run receipts")
        elif any(value is not None for value in phase_inputs):
            raise ValueError("real-elapsed inputs are only valid for the fixed SDK phase family")
        if FixtureKind(self.fixture_kind).value not in FIXTURE_NODES:
            raise ValueError("one fixed fixture family required")
        if str(UUID(self.operation_id, version=4)) != self.operation_id or UUID(self.operation_id).version != 4:
            raise ValueError("fresh UUID4 resource operation required")
        package = Path(self.package_path)
        if (package.name==BETA1_PACKAGE_NAME and self.fixture_kind.startswith(("numeric","d13"))
                and self.fixture_kind not in BETA1_CURRENT_SUITE_KINDS):
            raise ValueError("Beta1 Numeric/D13 require the full current protected suite; no legacy pytest fallback")
        root = Path(self.frozen_rewrite_root)
        if (package.resolve(strict=True) != package or root.resolve(strict=True) != root
                or package.name not in PACKAGE_NAMES or package.parent.parent != Path(self.delivery_root)
                or root != package.parent / "source-input/rewrite"):
            raise ValueError("fixed selected-package source layout required")
        if self.fixture_kind != "b04" and self.fixture_kind not in SDK_M1_KINDS and (self.installed_root is None or not Path(self.installed_root).is_relative_to(
                Path(self.installed_stage_root))):
            raise ValueError("existing separately verified canonical installed stage required")
        for value in (self.package_sha256, self.manifest_sha256, self.helper_sha256,
                      self.dependency_sha256, self.request_sha256):
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("external byte pins required")
        if self.fixture_kind == "c09_current":
            _validate_c09_engineering_inventory_v1(self)
        elif self.engineering_inventory_sha256 is not None:
            raise ValueError("engineering inventory pin is only valid for current C09")
        if self.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(self):
            if self.phase_fixture_setup is None or self.phase_fixture_setup_sha256 is None:
                raise ValueError("pinned protected phase fixture setup required")
            if (len(self.phase_fixture_setup_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in self.phase_fixture_setup_sha256)):
                raise ValueError("external phase fixture setup byte pin required")
            _validate_phase_fixture_setup(self.phase_fixture_setup, self.phase_fixture_setup_sha256, self.phase_setup_root)
        elif self.phase_fixture_setup is not None or self.phase_fixture_setup_sha256 is not None:
            raise ValueError("phase fixture setup is only valid for the fixed protected phase kinds")
        if (Path(self.basetemp).resolve() != Path(self.basetemp)
                or Path(self.evidence_directory).resolve() != Path(self.evidence_directory)
                or not Path(self.basetemp).is_relative_to(Path(self.fixture_root)) or Path(self.basetemp) == Path(self.fixture_root)
                or not Path(self.evidence_directory).is_relative_to(Path(self.fixture_root)) or Path(self.evidence_directory) == Path(self.fixture_root)):
            raise ValueError("fresh ext4 fixture and private evidence paths required")


def _read(path):
    return path.read_text().strip()


def _write(path, value):
    with path.open("w") as stream:
        stream.write(value)


def _birth(pid):
    tail = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + tail[19]


def _event(path, name):
    return dict(line.split() for line in _read(path / "cgroup.events").splitlines())[name]


def _identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def _topology(parent):
    result = []
    for child in sorted(parent.iterdir()):
        if child.is_dir():
            result.append({"name": child.name, "identity": _identity(child),
                "populated": _event(child, "populated"),
                "subtree_control": _read(child / "cgroup.subtree_control")})
    return result


def _metrics(group):
    return {name: _read(group / name) if (group / name).exists() else None for name in METRICS}


def _members(app, *, capture_memory=False):
    result = []
    for pid in map(int, _read(app / "cgroup.procs").split()):
        try:
            status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            member = {"pid": pid, "birth": _birth(pid), "parent_pid": int(status["PPid"]),
                "uids": list(map(int, status["Uid"].split())), "nspid": list(map(int, status["NSpid"].split())),
                "cgroup": _read(Path(f"/proc/{pid}/cgroup")),
                "oom_score_adj": _read(Path(f"/proc/{pid}/oom_score_adj")),
                "affinity": sorted(os.sched_getaffinity(pid)),
                "scheduler_classes": {task.name: os.sched_getscheduler(int(task.name))
                    for task in Path(f"/proc/{pid}/task").iterdir()}}
            if capture_memory:
                member["memory_bytes"] = {name: int(status[name].split()[0]) * 1024
                    for name in ("VmRSS", "RssAnon", "RssFile", "RssShmem", "VmHWM", "VmData") if name in status}
            result.append(member)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def _descendant_ids(seed):
    result, pending = set(), [seed]
    while pending:
        parent = pending.pop()
        try:
            tasks = tuple(Path(f"/proc/{parent}/task").iterdir())
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                children = map(int, _read(task / "children").split())
                for child in children:
                    if child not in result:
                        result.add(child); pending.append(child)
            except FileNotFoundError:
                continue
    return result


def _private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def _pin_inputs_in_child(spec):
    if spec.fixture_kind == "c09_current":
        _validate_c09_engineering_inventory_v1(spec)
    inputs = ((spec.package_path, spec.package_sha256),
                      (str(Path(spec.frozen_rewrite_root) / FIXTURE_NODES[spec.fixture_kind][0].split("::")[0]), spec.helper_sha256),
                      (spec.dependency_manifest, spec.dependency_sha256),
                      (spec.approved_install_request, spec.request_sha256))
    if spec.fixture_kind == "sdk_real_elapsed":
        inputs += ((spec.real_elapsed_approval, spec.real_elapsed_approval_sha256),)
    for path, pin in inputs:
        digest = sha256()
        with open(path, "rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        if digest.hexdigest() != pin:
            raise ValueError("selected fixture input bytes changed before exec")
    if spec.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(spec):
        _validate_phase_fixture_setup(spec.phase_fixture_setup, spec.phase_fixture_setup_sha256, spec.phase_setup_root)


def _prepare_phase_child_paths_v1(spec):
    """Keep observer evidence private; give the fixed phase nodes their own workspace."""
    import pwd
    ordinary = pwd.getpwnam("ubuntu")
    if (os.geteuid() != 0 or spec.fixture_kind not in PHASE_FIXTURE_KINDS
            or (ordinary.pw_uid, ordinary.pw_gid) != (1000, 1000)):
        raise ValueError("fixed phase child requires its actual ubuntu identity")
    workspace = Path(spec.basetemp)
    if spec.fixture_kind == "c09_current":
        os.chown(workspace.parent,0,1000)
        workspace.parent.chmod(0o710)
    for directory in (workspace, workspace / "evidence", workspace.parent / "sdk-root"):
        directory.mkdir(mode=0o700)
        os.chown(directory, 1000, 1000)
        directory.chmod(0o700)


def _enter_phase_child_identity_v1():
    """Run only after Root has confirmed the original child's cgroup membership."""
    os.setgroups([1000])
    os.setgid(1000)
    os.setuid(1000)
    if (os.getresuid() != (1000, 1000, 1000)
            or os.getresgid() != (1000, 1000, 1000) or os.getgroups() != [1000]):
        raise ValueError("phase child did not enter its fixed ordinary identity")


def _fixed_child(spec_json):
    spec = OwnedResourceRunV1(**json.loads(spec_json))
    if spec.fixture_kind == "c09_current":
        raise ValueError("current C09 requires the Root-controlled four-phase harness, never a business-loaded pytest controller")
    if not _read(Path("/proc/self/cgroup")).endswith("/sylanne-owned-" + spec.operation_id + "/app"):
        raise ValueError("fixed fixture child must already be in its owned resource app")
    _pin_inputs_in_child(spec)
    # Test support is omitted from the installable package. Bind its ordinary
    # rewrite package to frozen engineering bytes before the installed root.
    # The canonical finder still binds every sylanne3 module to installed bytes.
    sys.path.insert(0, str(Path(spec.frozen_rewrite_root).parent))
    import rewrite
    if Path(rewrite.__file__).resolve() != Path(spec.frozen_rewrite_root) / "__init__.py":
        raise ValueError("test support package differs from the frozen engineering root")
    if spec.fixture_kind != "b04" and spec.fixture_kind not in SDK_M1_KINDS:
        installed = Path(spec.installed_root)
        if installed.resolve(strict=True) != installed:
            raise ValueError("actual canonical installed root required")
        if sha256((installed / "release-manifest.json").read_bytes()).hexdigest() != spec.manifest_sha256:
            raise ValueError("installed stage belongs to another selected package")
        sys.path.insert(0, str(installed)); sys.path.insert(1, spec.sdk_root)
        from _runtime_bootstrap import load_canonical_runtime_v1
        load_canonical_runtime_v1(installed)
        os.environ["SYLANNE_D04_INSTALLED_ROOT"] = str(installed)
    import pytest
    args = ["-q", "--maxfail=1", "-p", "no:cacheprovider", "-p", "pytest_asyncio.plugin", "--rootdir=" + spec.frozen_rewrite_root,
            *(str(Path(spec.frozen_rewrite_root) / node) for node in FIXTURE_NODES[spec.fixture_kind]),
            "--basetemp", str(Path(spec.basetemp) / "pytest")
            if spec.fixture_kind in PHASE_FIXTURE_KINDS else spec.basetemp]
    class Outcomes:
        def __init__(self):
            self.collected = self.passed = self.failed = self.skipped = 0

        def pytest_collection_finish(self, session):
            self.collected = len(session.items)

        def pytest_collectreport(self, report):
            if report.failed:
                self.failed += 1
            elif report.skipped:
                self.skipped += 1

        def pytest_runtest_logreport(self, report):
            if report.failed:
                self.failed += 1
            elif report.skipped:
                self.skipped += 1
            elif report.when == "call" and report.passed:
                self.passed += 1

    outcomes = Outcomes()
    result = int(pytest.main(args, plugins=[outcomes]))
    all_executed = (outcomes.collected > 0 and outcomes.passed == outcomes.collected
                    and outcomes.failed == 0 and outcomes.skipped == 0)
    effective_exit = result if result else (0 if all_executed else 2)
    _private_json((Path(spec.basetemp) / "evidence" if spec.fixture_kind in PHASE_FIXTURE_KINDS
                   else Path(spec.evidence_directory)) / "pytest-outcomes.json", {
        "pytest_exit_code": result, "effective_exit_code": effective_exit,
        "collected": outcomes.collected, "passed": outcomes.passed,
        "failed_reports": outcomes.failed, "skipped_reports": outcomes.skipped})
    return effective_exit


def run_owned_resource_profile_v1(spec, *, cgroup_parent="/sys/fs/cgroup", timeout_seconds=1000):
    """Run one fixed family, stopping at its first failure; caller owns all gates.

    No business imports occur here. Limit refusal/OOM/timeout is a failed
    fixture result, never a production Stop receipt or a replacement operation.
    """
    if type(spec) is not OwnedResourceRunV1 or os.geteuid() != 0:
        raise ValueError("explicit fixed fixture and existing root resource authority required")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 1000:
        raise ValueError("original bounded fixture deadline required")
    if spec.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(spec):
        _validate_phase_fixture_setup(spec.phase_fixture_setup, spec.phase_fixture_setup_sha256, spec.phase_setup_root)
    if (len(tuple(Path("/proc/self/task").iterdir())) != 1
            or any(name == "sylanne3" or name.startswith("sylanne3.") or name == "astrbot"
                   or name.startswith("astrbot.") or name == "_runtime_bootstrap" for name in sys.modules)):
        raise ValueError("fresh single-thread stdlib observer required before application imports")
    evidence = Path(spec.evidence_directory)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if evidence.stat().st_uid != 0 or evidence.stat().st_mode & 0o077:
        raise ValueError("root-private ext4 evidence directory required")
    if Path(spec.basetemp).exists():
        raise ValueError("fresh fixture basetemp required")
    if spec.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(spec):
        _prepare_phase_child_paths_v1(spec)
    command = [PYTHON, "-B", str(Path(__file__).resolve()), "--fixed-child", json.dumps(asdict(spec))]
    environment = dict(os.environ,
        PYTHONPATH=os.pathsep.join((str(Path(spec.frozen_rewrite_root).parent), spec.frozen_rewrite_root)),
        ASTRBOT_ROOT=str(Path(spec.basetemp).parent / "sdk-root"), PYTHONDONTWRITEBYTECODE="1",
        SYLANNE_B04_PACKAGE=spec.package_path, SYLANNE_B04_PACKAGE_SHA256=spec.package_sha256,
        SYLANNE_B04_MANIFEST_SHA256=spec.manifest_sha256,
        SYLANNE_B04_DEPENDENCY_MANIFEST=spec.dependency_manifest,
        SYLANNE_B04_APPROVED_INSTALL_REQUEST=spec.approved_install_request)
    if spec.fixture_kind in SDK_M1_KINDS:
        environment.update({name.replace("SYLANNE_B04_", "SYLANNE_SDK_M1_"): environment[name]
            for name in ("SYLANNE_B04_PACKAGE", "SYLANNE_B04_PACKAGE_SHA256",
                "SYLANNE_B04_MANIFEST_SHA256", "SYLANNE_B04_DEPENDENCY_MANIFEST",
                "SYLANNE_B04_APPROVED_INSTALL_REQUEST")})
    for name in ("PHASE", "DIRECTORY", "APPROVAL"):
        environment.pop("SYLANNE_SDK_M1_REAL_ELAPSED_" + name, None)
    if spec.fixture_kind == "sdk_real_elapsed":
        environment.update(SYLANNE_SDK_M1_REAL_ELAPSED_PHASE=spec.real_elapsed_phase,
            SYLANNE_SDK_M1_REAL_ELAPSED_DIRECTORY=spec.real_elapsed_directory,
            SYLANNE_SDK_M1_REAL_ELAPSED_APPROVAL=spec.real_elapsed_approval)
    for name in ("INSTALLED_ROOT", "MANIFEST_SHA256", "TEST_ROOT", "ENGINEERING_INVENTORY_SHA256"):
        environment.pop("SYLANNE_C09_" + name, None)
    if spec.fixture_kind == "c09_current":
        environment.update(SYLANNE_C09_INSTALLED_ROOT=spec.installed_root,
            SYLANNE_C09_MANIFEST_SHA256=spec.manifest_sha256,
            SYLANNE_C09_TEST_ROOT=str(Path(spec.frozen_rewrite_root).parent),
            SYLANNE_C09_ENGINEERING_INVENTORY_SHA256=spec.engineering_inventory_sha256,
            SYLANNE_QUAL_SDK_ROOT=spec.sdk_root)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP", None)
    environment.pop("SYLANNE_L02_FIXTURE_SETUP", None)
    if spec.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(spec):
        environment["SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP"] = spec.phase_fixture_setup
        if spec.fixture_kind in L02_FIXTURE_KINDS:
            environment["SYLANNE_L02_FIXTURE_SETUP"] = spec.phase_fixture_setup
        environment["SYLANNE_PHASE_APPLICATION_EVIDENCE"] = str(Path(spec.basetemp) / "evidence")
    environment.pop("SYLANNE_B04_DIAGNOSTIC_MODE", None)
    if spec.fixture_kind == "b04_probe_diagnostic":
        environment["SYLANNE_B04_DIAGNOSTIC_MODE"] = "first-selection-probe-only"
    parent = Path(cgroup_parent)
    run = app = None
    run_owned = False
    app_owned = False
    added = set()
    initial = topology = None
    pid = handle = None
    descriptors = []
    streams = []
    started = time.monotonic()
    summary = {"status": "RESOURCE_SETUP_NOT_RUN", "operation_id": spec.operation_id,
        "command": command, "package_sha256": spec.package_sha256,
        "manifest_sha256": spec.manifest_sha256, "profile": {"run": RUN_CONTROLS, "app": APP_CONTROLS},
        "requested_run_memory_budget_bytes": RUN_MEMORY_BUDGET_BYTES, "kernel_page_bytes": PAGE_BYTES,
        "qualification_scope": "complete fixture subtree only; whole machine target unverified",
        "actual_inputs": asdict(spec), "observer_executable": sys.executable,
        "observer_executable_sha256": sha256(Path(sys.executable).read_bytes()).hexdigest(),
        "declared_timeout_seconds": timeout_seconds, "log_limit_bytes": LOG_LIMIT,
        "cgroup_parent": str(parent),
        "pytest_outcomes_path": str((Path(spec.basetemp) / "evidence" if spec.fixture_kind in PHASE_FIXTURE_KINDS
                                    else evidence) / "pytest-outcomes.json")}
    try:
        mounts = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                  if " - cgroup2 " in line]
        if len(mounts) != 1 or mounts[0][3] != "/":
            raise ValueError("one actual full cgroup2 mount required")
        mount = Path(mounts[0][4])
        if parent.resolve(strict=True) != parent or not parent.is_relative_to(mount):
            raise ValueError("canonical actual cgroup parent required")
        relative = "/" + str(parent.relative_to(mount)).strip(".")
        if parent != mount and _read(parent / "cgroup.type") != "domain":
            raise ValueError("actual domain resource parent required")
        topology = _topology(parent)
        initial = set(_read(parent / "cgroup.subtree_control").split())
        available = set(_read(parent / "cgroup.controllers").split())
        required_controllers={"cpu", "memory", "pids"} if spec.fixture_kind=="sdk_d13_v7_256" else {"cpu", "memory"}
        if not required_controllers <= available:
            raise ValueError("actual CPU/memory controllers unavailable")
        missing = required_controllers - initial
        summary["before"] = {"mount": str(mount), "parent": str(parent), "parent_identity": _identity(parent),
            "parent_limits": {n: _read(parent / n) if (parent / n).exists() else None for n in RUN_CONTROLS},
            "self_cgroup": _read(Path("/proc/self/cgroup")), "parent_tasks": _read(parent / "cgroup.procs"),
            "parent_process_originals": _members(parent),
            "controllers": sorted(available), "subtree_control": sorted(initial), "children": topology}
        summary["before"]["ancestor_limits"] = [
            {"path": str(ancestor), "controls": {name: _read(ancestor / name) if (ancestor / name).exists() else None
                for name in RUN_CONTROLS}}
            for ancestor in (parent, *parent.parents) if ancestor.is_relative_to(mount)]
        if missing:
            if any(child["populated"] != "0" for child in topology):
                raise ValueError("unrelated active child workloads prevent isolated controller enablement")
            if parent != mount and _read(parent / "cgroup.procs"):
                raise ValueError("non-root domain parent has internal tasks")
            try:
                _write(parent / "cgroup.subtree_control", " ".join("+" + token for token in sorted(missing)))
            finally:
                added = (set(_read(parent / "cgroup.subtree_control").split()) - initial) & missing
            if not missing <= added:
                raise ValueError("controller enablement readback differs")
        run = parent / ("sylanne-owned-" + spec.operation_id)
        run.mkdir()
        run_owned = True
        run_id = _identity(run)
        for name, value in RUN_CONTROLS.items():
            _write(run / name, value)
            if _read(run / name) != value:
                raise ValueError("owned run control readback differs")
        _write(run / "cgroup.subtree_control", " ".join("+"+name for name in sorted(required_controllers)))
        app = run / "app"
        app.mkdir()
        app_owned = True
        app_id = _identity(app)
        for name, value in APP_CONTROLS.items():
            _write(app / name, value)
            if _read(app / name) != value:
                raise ValueError("owned app control readback differs")
        summary["effective_controls"] = {"run": {n: _read(run / n) for n in RUN_CONTROLS},
            "app": {n: _read(app / n) for n in (*APP_CONTROLS, "cpu.max")},
            "run_identity": run_id, "app_identity": app_id, "added_parent_tokens": sorted(added)}
        if _uses_beta1_current_suite_v3(spec):
            from rewrite.host_tests.alpha1.c09_root_phase_harness_v3 import run_root_controlled_beta1_suite_v3
            summary.pop("pytest_outcomes_path")
            summary.update(run_root_controlled_beta1_suite_v3(spec,app=app,run=run,environment=environment,
                started=started,deadline=started+timeout_seconds,profile=globals()))
        elif spec.fixture_kind == "c09_current":
            from rewrite.host_tests.alpha1.c09_root_phase_harness_v3 import run_root_controlled_four_phase_v3
            summary.pop("pytest_outcomes_path")
            summary.update(run_root_controlled_four_phase_v3(spec,app=app,run=run,environment=environment,
                started=started,deadline=started+timeout_seconds,profile=globals()))
        else:
            placement = os.open(app / "cgroup.procs", os.O_WRONLY)
            ready_r, ready_w = os.pipe()
            go_r, go_w = os.pipe()
            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()
            descriptors = [placement, ready_r, ready_w, go_r, go_w, out_r, out_w, err_r, err_w]
            log_fds = {out_r: os.open(evidence / "stdout.private.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                       err_r: os.open(evidence / "stderr.private.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)}
            streams = list(log_fds.values())
            counts = {fd: 0 for fd in log_fds}
            metrics_fd = os.open(evidence / "resources.private.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            streams.append(metrics_fd)
            metric_bytes = 0
            pid = os.fork()
            if pid == 0:
                try:
                    for fd in (ready_r, go_w, out_r, err_r): os.close(fd)
                    os.dup2(out_w, 1); os.dup2(err_w, 2)
                    os.write(placement, str(os.getpid()).encode())
                    os.write(ready_w, b"PLACED\n")
                    if os.read(go_r, 2) != b"GO": os._exit(125)
                    for fd in (placement, ready_w, go_r, out_w, err_w): os.close(fd)
                    os.chdir(spec.frozen_rewrite_root)
                    if spec.fixture_kind in PHASE_FIXTURE_KINDS or _uses_beta1_current_suite_v3(spec):
                        _enter_phase_child_identity_v1()
                    os.execve(PYTHON, command, environment)
                except BaseException as error:
                    os.write(2, (type(error).__name__ + " before fixed exec\n").encode())
                    os._exit(126)
            handle = os.pidfd_open(pid)
            original_birth = _birth(pid)
            for fd in (placement, ready_w, go_r, out_w, err_w):
                os.close(fd); descriptors.remove(fd)
            if not select.select([ready_r, handle], [], [], 10)[0] or os.read(ready_r, 7) != b"PLACED\n":
                raise ValueError("fresh owned child self-placement not confirmed")
            expected_cgroup = relative.rstrip("/") + "/" + run.name + "/app"
            if (_birth(pid) != original_birth or _read(Path(f"/proc/{pid}/cgroup")) != "0::" + expected_cgroup
                    or _read(app / "cgroup.procs") != str(pid) or _identity(app) != app_id or _identity(run) != run_id):
                raise ValueError("original child/group membership differs before GO")
            for group, controls in ((run, RUN_CONTROLS), (app, APP_CONTROLS)):
                if any(_read(group / name) != value for name, value in controls.items()):
                    raise ValueError("effective profile changed before GO")
            summary["seed_process"] = {"pid": pid, "birth": original_birth, "cgroup": expected_cgroup}
            os.write(go_w, b"GO");os.close(go_w);descriptors.remove(go_w)
            os.close(ready_r);descriptors.remove(ready_r)
            for fd in (out_r, err_r): os.set_blocking(fd, False)
            deadline = started + timeout_seconds
            sampling = 0.0
            observed_births = {pid: original_birth}
            while True:
                if time.monotonic() >= sampling:
                    inventory = _members(app, capture_memory=spec.fixture_kind.startswith("b04"))
                    for member in inventory: observed_births[member["pid"]] = member["birth"]
                    for member_pid in _descendant_ids(pid) | set(observed_births):
                        try:
                            if member_pid in observed_births and _birth(member_pid) != observed_births[member_pid]:
                                continue  # A different birth is not this invocation's process.
                            if _read(Path(f"/proc/{member_pid}/cgroup")) != "0::" + expected_cgroup:
                                raise ValueError("actual original descendant escaped owned resource profile")
                        except FileNotFoundError:
                            continue
                    snapshot = {"observed_time_ns": time.time_ns(), "run": _metrics(run), "app": _metrics(app),
                                "members": inventory}
                    encoded = (json.dumps(snapshot) + "\n").encode()
                    if metric_bytes + len(encoded) > LOG_LIMIT:
                        raise ValueError("bounded resource observation capture exhausted")
                    os.write(metrics_fd, encoded); metric_bytes += len(encoded)
                    sampling = time.monotonic() + 0.5
                    if any(member["cgroup"] != "0::" + expected_cgroup
                           or any(policy not in (0, 3, 5) for policy in member["scheduler_classes"].values())
                           for member in inventory):
                        raise ValueError("observed process escaped fixed membership/fair CPU profile")
                ended = bool(select.select([handle], [], [], 0)[0])
                if time.monotonic() >= deadline:
                    raise TimeoutError("original bounded resource fixture deadline")
                readable = select.select([*log_fds], [], [], 0.1)[0] if log_fds else []
                for fd in readable:
                    data = os.read(fd, 65536)
                    if not data:
                        os.close(fd); descriptors.remove(fd); log_fds.pop(fd)
                    else:
                        if counts[fd] + len(data) > LOG_LIMIT:
                            raise ValueError("bounded private log capture exhausted")
                        os.write(log_fds[fd], data); counts[fd] += len(data)
                if ended and not log_fds: break
            _, status = os.waitpid(pid, 0)
            summary.update(status="FIXTURE_EXIT_OBSERVED_NOT_QUALIFICATION", actual_exit=os.waitstatus_to_exitcode(status),
                           original_pidfd_ready=True, elapsed_seconds=time.monotonic() - started)
    except BaseException as error:
        summary.update(status="RESOURCE_SETUP_OR_RUN_FAILED", first_failure={"type": type(error).__name__,
            "errno": error.errno if isinstance(error, OSError) else None,
            "frames": [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                       for frame in traceback.extract_tb(error.__traceback__)],
            "before_owned_mkdir": not run_owned, "elapsed_seconds": time.monotonic() - started})
    finally:
        try:
            if run_owned and run.exists():
                if (_identity(run) != run_id or app_owned and _identity(app) != app_id
                        or {p.name for p in run.iterdir() if p.is_dir()} != ({"app"} if app_owned else set())):
                    raise ValueError("owned resource directory identity changed before cleanup")
                summary["final_metrics_before_cleanup"] = {"run": _metrics(run), "app": _metrics(app) if app_owned else None}
                events = dict(line.split() for line in summary["final_metrics_before_cleanup"]["run"]["memory.events"].splitlines())
                summary["kernel_oom_observed"] = any(int(events[name]) > 0 for name in ("oom", "oom_kill", "oom_group_kill") if name in events)
                if summary["kernel_oom_observed"]:
                    summary["status"] = "RESOURCE_OOM_FAILED_HOLD"
                if handle is not None and not select.select([handle], [], [], 0)[0]:
                    signal.pidfd_send_signal(handle, signal.SIGTERM)
                if _event(run, "populated") != "0":
                    kill = run / "cgroup.kill"
                    if kill.exists():
                        _write(kill, "1"); summary["owned_environment_group_kill"] = True
                        end = time.monotonic() + 10
                        while _event(run, "populated") != "0" and time.monotonic() < end: time.sleep(0.05)
                if handle is not None:
                    summary["original_pidfd_ready_after_cleanup"] = bool(select.select([handle], [], [], 0)[0])
                    if summary["original_pidfd_ready_after_cleanup"]:
                        try:
                            _, status = os.waitpid(pid, 0)
                            summary.setdefault("actual_exit", os.waitstatus_to_exitcode(status))
                        except ChildProcessError:
                            pass
                summary["recursive_populated_after_cleanup"] = _event(run, "populated")
                if summary["recursive_populated_after_cleanup"] == "0" and (handle is None or summary["original_pidfd_ready_after_cleanup"]):
                    if app_owned: app.rmdir()
                    run.rmdir(); summary["owned_groups_removed"] = True
                else:
                    summary["owned_groups_removed"] = False
            if added:
                current = set(_read(parent / "cgroup.subtree_control").split())
                # Existing empty children can adopt controller settings without
                # changing their directory, populated or subtree-control state.
                # Only an initially empty parent proves no such dependency.
                if (not topology and (run is None or not run.exists())
                        and _topology(parent) == topology and current == initial | added):
                    _write(parent / "cgroup.subtree_control", " ".join("-" + token for token in sorted(added)))
                    summary["added_tokens_restored"] = set(_read(parent / "cgroup.subtree_control").split()) == initial
                else:
                    summary["added_tokens_restored"] = False
                    summary["cleanup_complete"] = False
                    summary["controller_restore_hold"] = "external_controller_use_not_proved_absent"
        except (OSError, ValueError) as cleanup_error:
            summary["cleanup_complete"] = False
            summary["cleanup_failure"] = {"type": type(cleanup_error).__name__,
                "errno": cleanup_error.errno if isinstance(cleanup_error, OSError) else None}
        for fd in streams: os.fsync(fd);os.close(fd)
        for fd in descriptors: os.close(fd)
        if handle is not None: os.close(handle)
        _private_json(evidence / "resource-run-original.json", summary)
    return summary


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--fixed-child":
        raise SystemExit("only the fixed owned fixture child entry is supported")
    raise SystemExit(_fixed_child(sys.argv[2]))
