"""Authenticated selection history, distinct from a registry of candidates.

This reader fails closed until the actual installer origin and actual signed
compatibility/backup observations exist. A stage name or caller-provided list
of registered manifests never proves historical eligibility.
"""
from dataclasses import asdict, dataclass
import hashlib

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2, decode_package_selection_v2, _sha, _canonical
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
from .d12_initial_selection_original_v1 import read_initial_selection_original_v1
from .d12_managed_backup_v2 import decode_managed_backup_v2, decode_backup_source_v2
from .d12_historical_manifest_inventory_v1 import decode_historical_manifest_inventory_v1
from ..runtime_contracts import canonical_digest

COMPATIBILITY_SCHEMA = "d12.package-compatibility-original.v2"
_COMPATIBILITY_FIELDS = frozenset(("schema", "operation_id", "accepted_original_digest",
    "before_selection_digest", "candidate_cohort_ref", "candidate_cohort_digest", "candidate_manifest_sha256",
    "backup_observation_ref", "backup_observation_digest", "history_inventory_digest", "storage_identity_digest",
    "logical_inventory_digest", "readers_digest", "compatibility_plan_digest", "disposition", "compatibility_digest"))


def decode_package_compatibility_original_v2(raw):
    if (type(raw) is not dict or set(raw) != _COMPATIBILITY_FIELDS
            or raw["schema"] != COMPATIBILITY_SCHEMA or raw["disposition"] != "same_schema_current_data"
            or any(type(raw[key]) is not str or not raw[key] for key in
                ("operation_id", "candidate_cohort_ref", "backup_observation_ref"))
            or any(not _sha(raw[key]) for key in _COMPATIBILITY_FIELDS - {
                "schema", "operation_id", "candidate_cohort_ref", "backup_observation_ref", "disposition"})):
        raise AuthorityUnavailable("closed actual package compatibility original required")
    body = dict(raw); body.pop("compatibility_digest")
    if canonical_digest(body) != raw["compatibility_digest"]:
        raise AuthorityUnavailable("package compatibility original commitment differs")
    return raw


@dataclass(frozen=True, slots=True)
class PackageSelectionHistoryV1:
    installation_id: str
    authority_id: str
    authority_namespace: str
    selection_digest: str
    initial_original_digest: str
    ever_active_manifests: tuple[str, ...]
    transitions: tuple[tuple[str, str, str, str], ...]
    qualification_stage: str
    history_digest: str


class InstalledPackageHistoryEligibilityV1:
    def __init__(self, *, package_files, supervisor_journal, authority_namespace):
        if (type(package_files) is not InstalledPackageSelectionFilesV2
                or type(supervisor_journal) is not InstalledPackageSupervisorJournalV2
                or package_files.control_directory != supervisor_journal.directory
                or type(authority_namespace) is not str or not authority_namespace):
            raise AuthorityUnavailable("actual common protected selection history required")
        self.files, self.journal, self.namespace = package_files, supervisor_journal, authority_namespace

    def _operation(self, selection):
        intent = self.journal.read_verified_intent_v2(selection.operation_id)
        if (intent is None or intent.installation_id != selection.installation_id
                or self.namespace not in intent.namespace_cohort):
            raise AuthorityUnavailable("selected operation has no actual accepted original")
        receipts = self.journal.read_verified_receipts_v2(selection.operation_id)
        observations = {}
        for receipt in receipts:
            for reference, commitment in receipt.observation_refs:
                if reference == intent.accepted_original_ref:
                    if commitment != intent.digest:
                        raise AuthorityUnavailable("accepted package observation differs")
                    continue
                observed = self.journal.read_verified_observation_v2(selection.operation_id, reference)
                if observed.observation_digest != commitment:
                    raise AuthorityUnavailable("package observation receipt differs")
                observations[reference] = observed
        return intent, receipts, observations

    def _require_actual_activation(self, receipt, *, intent, selection, observations, compatibility, receipts):
        from .d12_package_bootstrap_v2 import (
            decode_package_activation_original_v2, decode_package_bootstrap_original_v2,
        )
        values = [observations[ref] for ref, _ in receipt.observation_refs
            if ref in observations and observations[ref].kind == "package_activation"]
        if len(values) != 1:
            raise AuthorityUnavailable("ever-active package needs its actual activation original")
        active = decode_package_activation_original_v2(values[0].body)
        def stage_intent_digest(row):
            return hashlib.sha256(_canonical(dict(operation_id=row.operation_id,
                stage_sequence=row.stage_sequence, stage=row.stage,
                prior_receipt_digest=row.prior_receipt_digest,
                accepted_original_digest=row.accepted_original_digest,
                schema="sylanne3.d12.supervisor-stage-intent.v2"))).hexdigest()
        if (active["state"] != receipt.stage or active["operation_id"] != intent.operation_id
                or active["accepted_original_digest"] != intent.digest or active["namespace"] != self.namespace
                or active["installation_id"] != selection.installation_id
                or active["selection_digest"] != selection.selection_digest
                or active["package_epoch"] != selection.package_epoch
                or active["cohort_digest"] != selection.cohort_digest
                or active["manifest_sha256"] != selection.manifest_sha256
                or active["supervisor_intent_digest"] != stage_intent_digest(receipt)
                or active["compatibility_observation_ref"] != compatibility.observation_ref
                or active["compatibility_observation_digest"] != compatibility.observation_digest):
            raise AuthorityUnavailable("actual activation differs from selected compatible package")
        for role in ("authority", "host"):
            matching = [value for value in observations.values() if value.kind == "package_bootstrap"
                and value.body.get("original_ref") == active[role + "_bootstrap_ref"]]
            if len(matching) != 1:
                raise AuthorityUnavailable("actual activation lacks both original process readiness proofs")
            bootstrap = decode_package_bootstrap_original_v2(matching[0].body)
            prefix = "rollback_" if active["maintenance_phase"] == "rollback" else ""
            expected_stage = prefix + ("authority_bootstrap_ready" if role == "authority" else "bootstrap_ready")
            boot_receipts = [row for row in receipts if row.stage == expected_stage
                and (matching[0].observation_ref, matching[0].observation_digest) in row.observation_refs
                and row.stage_sequence < receipt.stage_sequence]
            if (bootstrap["service_role"] != role
                    or len(boot_receipts) != 1
                    or bootstrap["supervisor_intent_digest"] != stage_intent_digest(boot_receipts[0])
                    or bootstrap["original_digest"] != active[role + "_bootstrap_digest"]
                    or any(bootstrap[key] != active[key] for key in ("operation_id", "accepted_original_digest",
                        "namespace", "installation_id", "selection_digest", "cohort_digest", "manifest_sha256",
                        "package_epoch", "maintenance_phase", "compatibility_observation_ref", "compatibility_observation_digest"))):
                raise AuthorityUnavailable("actual activation/bootstrap identities differ")

    def read_actual_selection_history_v1(self):
        selected, current_cohort, _ = self.files.read_selected_configuration_cohort_v2()
        initial = read_initial_selection_original_v1(package_files=self.files, supervisor_journal=self.journal)
        if (initial.installation_id != selected.installation_id or self.namespace not in initial.namespace_cohort
                or initial.identity_commitment != current_cohort.identity_commitment):
            raise AuthorityUnavailable("selected package chain has a different installer origin")
        selection = selected
        active = {initial.selection.manifest_sha256}
        transitions = []; seen = set(); stage = "initial_active"
        while selection.revision:
            if selection.selection_digest in seen or len(seen) >= 128:
                raise AuthorityUnavailable("package history cycles or exceeds fixed bound")
            seen.add(selection.selection_digest)
            intent, receipts, observations = self._operation(selection)
            candidates = []
            for receipt in receipts:
                if receipt.stage not in {"package_switched", "rollback_package_switched"}:
                    continue
                values = [observations[ref] for ref, _ in receipt.observation_refs if ref in observations]
                if any(value.kind == "package_selection" and decode_package_selection_v2(value.body) == selection for value in values):
                    candidates.append(receipt)
            if len(candidates) != 1:
                raise AuthorityUnavailable("selected package has no unique actual pointer-switch observation")
            switched = candidates[0]
            rollback = switched.stage == "rollback_package_switched"
            predecessors = {decode_package_selection_v2(value.body) for value in observations.values()
                if value.kind == "package_selection" and value.body.get("selection_digest") == selection.prior_selection_digest}
            if len(predecessors) != 1:
                raise AuthorityUnavailable("selected package predecessor was not actually observed")
            before = predecessors.pop()
            if (selection.revision != before.revision + 1 or selection.package_epoch != before.package_epoch + 1
                    or selection.installation_id != before.installation_id or intent.authority_id != initial.authority_id):
                raise AuthorityUnavailable("package selection history is not continuous")
            if not rollback and (before.selection_digest != intent.expected_selection_digest
                    or before.revision != intent.expected_selection_revision or before.package_epoch != intent.expected_package_epoch
                    or before.manifest_sha256 != intent.old_manifest_sha256 or before.cohort_digest != intent.old_cohort_digest
                    or selection.manifest_sha256 != intent.candidate_manifest_sha256
                    or selection.cohort_ref != intent.candidate_cohort_ref or selection.cohort_digest != intent.candidate_cohort_digest):
                raise AuthorityUnavailable("actual forward switch differs from accepted scope")
            if rollback and (selection.manifest_sha256 != intent.old_manifest_sha256
                    or selection.cohort_ref != intent.old_cohort_ref or selection.cohort_digest != intent.old_cohort_digest):
                raise AuthorityUnavailable("actual rollback selected an unaccepted package")
            compat_stage = "rollback_compatible_current_data" if rollback else "compatible_no_data_migration"
            compats = [receipt for receipt in receipts if receipt.stage == compat_stage and receipt.stage_sequence < switched.stage_sequence]
            if not compats:
                raise AuthorityUnavailable("actual switch lacks its prior compatibility receipt")
            receipt = compats[-1]
            values = [observations[ref] for ref, _ in receipt.observation_refs if ref in observations]
            values = [value for value in values if value.kind == "package_compatibility"]
            if len(values) != 1:
                raise AuthorityUnavailable("package compatibility needs its fixed actual observation, not a stage label")
            compatibility_observation = values[0]
            compatible = decode_package_compatibility_original_v2(compatibility_observation.body)
            if (compatible["operation_id"] != intent.operation_id or compatible["accepted_original_digest"] != intent.digest
                    or compatible["before_selection_digest"] != before.selection_digest
                    or compatible["candidate_manifest_sha256"] != selection.manifest_sha256
                    or compatible["candidate_cohort_ref"] != selection.cohort_ref
                    or compatible["candidate_cohort_digest"] != selection.cohort_digest
                    or compatible["compatibility_plan_digest"] != intent.compatibility_plan_digest):
                raise AuthorityUnavailable("compatibility does not describe this actual switch")
            backup_observation = observations.get(compatible["backup_observation_ref"])
            if (backup_observation is None or backup_observation.kind != "managed_backup"
                    or backup_observation.observation_digest != compatible["backup_observation_digest"]):
                raise AuthorityUnavailable("compatibility has no authenticated exact managed backup")
            backup = decode_managed_backup_v2(backup_observation.body)
            source_observation = observations.get(backup["source_observation_ref"])
            if (source_observation is None or source_observation.kind != "backup_source"
                    or source_observation.observation_digest != backup["source_observation_digest"]):
                raise AuthorityUnavailable("backup has no actual authenticated source observation")
            source = decode_backup_source_v2(source_observation.body)
            if (source["backup_phase"] != ("rollback" if rollback else "forward")
                    or backup["backup_phase"] != source["backup_phase"]
                    or source["selection_digest"] != before.selection_digest or source["source_digest"] != backup["source_digest"]
                    or source["history_inventory"] != backup["history_inventory"]
                    or source["logical_inventories"] != {role: copy["logical_inventory"] for role, copy in backup["copies"].items()}):
                raise AuthorityUnavailable("backup was not qualified against this exact current-data predecessor")
            inventory = decode_historical_manifest_inventory_v1(backup["history_inventory"])
            if (backup["operation_id"] != intent.operation_id or backup["accepted_original_digest"] != intent.digest
                    or backup["namespace"] != self.namespace or backup["installation_id"] != selected.installation_id
                    or inventory["inventory_digest"] != compatible["history_inventory_digest"]
                    or canonical_digest(backup["storage_identity"]) != compatible["storage_identity_digest"]
                    or canonical_digest({role: copy["logical_inventory"] for role, copy in backup["copies"].items()})
                        != compatible["logical_inventory_digest"]):
                raise AuthorityUnavailable("compatibility backup/current obligations differ")
            terminal_stage = "rollback_complete" if rollback else "active"
            activations = [row for row in receipts if row.stage == terminal_stage and row.stage_sequence > switched.stage_sequence
                and not any(other.stage in {"rollback_retire_intent", "package_switched", "rollback_package_switched"}
                    and switched.stage_sequence < other.stage_sequence < row.stage_sequence for other in receipts)]
            if len(activations) > 1:
                raise AuthorityUnavailable("selected package has conflicting actual activation receipts")
            became_active = bool(activations)
            if became_active:
                self._require_actual_activation(activations[0], intent=intent, selection=selection,
                    observations=observations, compatibility=compatibility_observation, receipts=receipts)
                active.add(selection.manifest_sha256)
            if selection == selected:
                stage = terminal_stage if became_active else ("rollback_pending_readiness" if rollback else "switched_pending_readiness")
                later = [r for r in receipts if r.stage_sequence > switched.stage_sequence]
                if any(r.stage == "unknown" for r in later):
                    raise AuthorityUnavailable("unknown package side effect is not a bootstrap qualification")
            transitions.append((selection.selection_digest, switched.receipt_digest,
                compatibility_observation.observation_digest, backup["manifest_digest"]))
            selection = before
        if selection != initial.selection:
            raise AuthorityUnavailable("package history does not terminate at its actual signed installer origin")
        if self.files.read_selected_package_v2()[0] != selected:
            raise AuthorityUnavailable("package selection changed during historical proof")
        body = dict(installation_id=selected.installation_id, authority_id=initial.authority_id,
            authority_namespace=self.namespace, selection_digest=selected.selection_digest,
            initial_original_digest=initial.original_digest, ever_active_manifests=tuple(sorted(active)),
            transitions=tuple(reversed(transitions)), qualification_stage=stage)
        return PackageSelectionHistoryV1(**body, history_digest=canonical_digest(body))
