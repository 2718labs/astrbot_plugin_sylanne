"""Installed passive verifiers for C09 before any ordinary Core is constructed.

Construction uses the same protected deployment keys and formal package gates
as live composition. These readers issue no permit, claim or completion ACK.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import hmac
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize


class InstalledC09OriginalVerifierV1:
    def __init__(self, *, config, control, core_db, business_db, execution_reader, kind, algorithm=None):
        from .deployment_config import AuthorityDeploymentConfig
        from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
        from .c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
        from .c09_storage_control_v1 import C09StorageControlV1
        from .daemon import _installed_file
        from .c09_connection_state_v1 import authority_id_in_tx_v1
        if (type(config) is not AuthorityDeploymentConfig or type(control) is not C09StorageControlV1
                or type(execution_reader) is not C09ExecutionOriginalsConnectionV1
                or type(config.c09_maintenance_factory) is not InstalledC09MaintenanceFactoryV1
                or not core_db.in_transaction or not business_db.in_transaction
                or kind not in {"numeric", "authored_root", "series", "offline_tick", "life", "internal"}):
            raise AuthorityUnavailable("actual installed C09 verification composition required")
        control.lease.require_held()
        factory = config.c09_maintenance_factory
        self.namespace = factory.namespace
        self.installation_id = control.installation_id
        self.authority_namespace = execution_reader.namespace
        self.authority_id = authority_id_in_tx_v1(core_db)
        self.journal, self.business, self.kind = execution_reader, business_db, kind
        self.resource_issuer, self.body_authority = factory.resource_issuer, factory.body_authority
        model = (config.natural_model_authorities_v2 or {}).get(self.authority_namespace)
        if (model is None or self.authority_id != control.authority_id
                or model.d11_issuer.resource_issuer is not self.resource_issuer):
            raise AuthorityUnavailable("C09 actual installed budget/resource issuers differ")
        self.budget_issuer = self.issuer = model.d11_issuer
        self.historical_recipe = None
        if kind in {"offline_tick", "life"}:
            bundle = model.installation_bundle
            work_kind = "d10.offline_observed_tick.v1" if kind == "offline_tick" else "d10.life.source_note.v1"
            if bundle is None or work_kind not in bundle.installation_policy.root_grant.allowed_work_kinds:
                raise AuthorityUnavailable("C09 offline installation policy absent")
            self._key = hmac.new(bundle.d11_signing_key,
                b"sylanne.authority.d11-offline-signing.v1" if kind == "offline_tick" else b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest()
            if kind == "life":
                from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
                installation = (config.c04_installations_v3 or {}).get(self.authority_namespace)
                if installation is None:
                    raise AuthorityUnavailable("C09 installed Life package absent")
                self.life_build = read_installed_d11_life_build_v1(installation.package_root, installation.formal_manifest_sha256)
            return
        installations = config.c04_installations_v2 if algorithm == "d06.association_activation.v2" else config.c04_installations_v3
        installation = (installations or {}).get(self.authority_namespace)
        if installation is None:
            raise AuthorityUnavailable("C09 actual formal algorithm installation absent")
        key = _installed_file(installation.component_key_path, "C09 protected component key").read_bytes()
        if len(key) != 32 or installation.component_key_path.resolve().is_relative_to(installation.package_root.resolve()):
            raise AuthorityUnavailable("C09 protected signing material differs")
        if kind == "internal":
            from ..host.installed_d06_build import verify_d06_algorithm_build, ENTRY_PATH, ENTRY_PATH_V3, KERNEL_PATH
            from .. import memory_association
            from ..domains.d06 import c04_work_algorithm_v3, c04_work_input_v2
            from pathlib import Path
            build = verify_d06_algorithm_build(installation.package_root, installation.formal_manifest_sha256,
                require_backend_runtime=True, algorithm_id=algorithm)
            entry = c04_work_input_v2 if algorithm == "d06.association_activation.v2" else c04_work_algorithm_v3
            entry_path = ENTRY_PATH if algorithm == "d06.association_activation.v2" else ENTRY_PATH_V3
            if (Path(entry.__file__).resolve() != (installation.package_root / entry_path).resolve()
                    or Path(memory_association.__file__).resolve() != (installation.package_root / KERNEL_PATH).resolve()):
                raise AuthorityUnavailable("C09 loaded internal algorithm differs from installed package")
            self.installed_algorithm_id = algorithm
            self.installed_build_digest = build["build_digest"].removeprefix("sha256:")
            self._key = key
            self.installed_runtime_verified = True
            return
        from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
        from ..host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
        identity_reader = read_installed_d04_root_identity_v3 if kind == "authored_root" else read_installed_d04_numeric_identity_v3
        self._identity = identity_reader(installation.package_root, installation.formal_manifest_sha256)
        self._key = hmac.new(key, b"sylanne.authority.d04-root-signing.v3" if kind == "authored_root"
            else b"sylanne.authority.d04-numeric-signing.v3", hashlib.sha256).digest()
        if model.installation_bundle is not None:
            from ..host.installed_package_history_v1 import build_installed_authority_d04_recipe_history_v1
            self.historical_recipe = build_installed_authority_d04_recipe_history_v1(model.installation_bundle, installation.package_root)

    def _sign(self, value):
        payload = asdict(value)
        payload.pop("signature")
        return hmac.new(self._key, canonical_serialize(payload).encode(), hashlib.sha256).hexdigest()

    def _binding(self, binding, *, kind):
        if (binding.namespace != self.namespace or binding.authority_namespace != self.authority_namespace
                or binding.authority_id != self.authority_id or binding.installation_id != self.installation_id):
            raise AuthorityUnavailable("C09 signed original crossed installed authority")
        if not all(getattr(binding, name) == value for name, value in self._identity.items()):
            if self.historical_recipe is None or kind == "series":
                raise AuthorityUnavailable("C09 historical recipe has no actual installed qualification")
            self.historical_recipe.require_qualified_recipe_v1(binding, kind=kind)

    def verify_numeric_journal_row_v3(self, journal, row):
        from .d04_numeric_journal_v3 import decode_numeric_row_v3, numeric_mutation_id_v3, numeric_cost_closure_basis_v3
        from .d04_numeric_contract_v3 import D04NumericTerminalV3, D04NumericMeasuredCostClosureV3
        from ..runtime.d04_numeric_cost_v3 import read_installed_d04_numeric_measurement_original_v3
        from ..runtime.restore_anchor import RestoreAnchor
        binding, claim, measurement = decode_numeric_row_v3(journal, row)
        self._binding(binding, kind="numeric")
        self._verify_claim(binding, claim, numeric_mutation_id_v3)
        if measurement is None:
            return binding, claim, None
        if read_installed_d04_numeric_measurement_original_v3(self.business, binding, claim) != measurement:
            raise AuthorityUnavailable("C09 actual numeric measurement differs")
        basis = numeric_cost_closure_basis_v3(row)
        if basis is None:
            terminal = D04NumericTerminalV3(binding, claim, measurement, numeric_mutation_id_v3(binding, "terminal"),
                row[0], row[6].removeprefix("sha256:"), "pending")
        else:
            terminal = D04NumericMeasuredCostClosureV3(binding, claim, measurement, basis["artifact_disposition"],
                basis["barrier_basis_digest"], RestoreAnchor(**basis["current_anchor"]),
                "d04-numeric-cost:" + binding.execution_id, row[0], row[6].removeprefix("sha256:"), "pending")
        return binding, claim, replace(terminal, signature=self._sign(terminal))

    def _verify_claim(self, binding, claim, mutation):
        if (claim.binding_digest != binding.digest or claim.execution_id != binding.execution_id
                or claim.executor_installation_id != self.installation_id
                or claim.claim_id != mutation(binding, "claim")
                or not hmac.compare_digest(claim.signature, self._sign(claim))):
            raise AuthorityUnavailable("C09 actual signed claim differs")

    def verify_root_journal_row_v3(self, journal, row):
        from .d04_root_execution_journal_v3 import decode_root_execution_row_v3, root_mutation_id_v3, root_cost_closure_basis_v3
        from .d04_root_execution_contract_v3 import (D04RootExecutionMeasurementV3, D04RootExecutionTerminalV3,
            D04RootMeasuredCostClosureV3, root_execution_from_wire_v3)
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        from ..runtime.restore_anchor import RestoreAnchor
        binding, claim, measurement = decode_root_execution_row_v3(journal, row)
        self._binding(binding, kind="authored_root")
        self._verify_claim(binding, claim, root_mutation_id_v3)
        if measurement is None:
            return binding, claim, None
        original = read_d04_original_v3(self.business, self.namespace, "root_measurement", binding.operation_id)
        actual = None if original is None else root_execution_from_wire_v3(original[0], D04RootExecutionMeasurementV3)
        if actual != measurement or actual.binding_digest != binding.digest or actual.claim_id != claim.claim_id:
            raise AuthorityUnavailable("C09 actual authored root measurement differs")
        basis = root_cost_closure_basis_v3(row)
        if basis is None:
            terminal = D04RootExecutionTerminalV3(binding, claim, measurement, root_mutation_id_v3(binding, "terminal"),
                row[0], row[6].removeprefix("sha256:"), "pending")
        else:
            terminal = D04RootMeasuredCostClosureV3(binding, claim, measurement, basis["artifact_disposition"],
                basis["barrier_basis_digest"], RestoreAnchor(**basis["current_anchor"]),
                "d04-root-cost:" + binding.execution_id, row[0], row[6].removeprefix("sha256:"), "pending")
        return binding, claim, replace(terminal, signature=self._sign(terminal))

    def verify_series_journal_row_v1(self, journal, row):
        from .d04_series_journal_v1 import decode_series_row_v1, mutation_id
        from .d04_series_contract_v1 import D04SeriesClaimV1, D04SeriesMeasurementV1, D04SeriesTerminalV1, from_wire
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        from ..runtime.d04_series_store_v1 import read_d04_series_chunk_math_v1
        binding, claim, measurement = decode_series_row_v1(journal, row)
        self._binding(binding.numeric, kind="series")
        if (claim.binding_digest != binding.digest or claim.claim_id != mutation_id(binding, "claim")
                or not hmac.compare_digest(claim.signature, self._sign(claim))):
            raise AuthorityUnavailable("C09 actual signed series claim differs")
        if measurement is None:
            return binding, claim, None
        original = read_d04_original_v3(self.business, self.namespace, "series_chunk_measurement", binding.numeric.operation_id)
        if (original is None or from_wire(original[0]["measurement"], D04SeriesMeasurementV1) != measurement
                or from_wire(original[0]["claim"], D04SeriesClaimV1) != claim):
            raise AuthorityUnavailable("C09 actual series measurement differs")
        chunk = read_d04_series_chunk_math_v1(self.business, self.namespace, binding.numeric.operation_id)
        if chunk is not None:
            artifact = read_d04_original_v3(self.business, self.namespace, "series_chunk_math", binding.numeric.operation_id)
            if (artifact[1] != original[0]["artifact_payload_digest"] or chunk.digest != measurement.chunk_math_digest
                    or canonical_digest(chunk.endpoints) != measurement.endpoint_digest
                    or (chunk.root_digest, chunk.plan_digest, chunk.start_step_index, chunk.end_step_index, chunk.predecessor_digest) !=
                       (binding.root_digest, binding.plan_digest, binding.start_step_index, binding.end_step_index, binding.predecessor_digest)):
                raise AuthorityUnavailable("C09 actual series native commitments differ")
        terminal = D04SeriesTerminalV1(binding, claim, measurement, mutation_id(binding, "terminal"),
            row[0], row[6].removeprefix("sha256:"), "pending")
        return binding, claim, replace(terminal, signature=self._sign(terminal))

    def verify_offline_tick_journal_row_v1(self, journal, row):
        from .d11_offline_tick_journal_v1 import decode_offline_tick_row_v1
        from .d11_offline_tick_contract_v1 import offline_tick_to_wire_v1
        binding, claim, terminal = decode_offline_tick_row_v1(journal, row)
        if (binding.namespace != self.namespace or binding.authority_namespace != self.authority_namespace
                or binding.authority_id != self.authority_id or binding.installation_id != self.installation_id):
            raise AuthorityUnavailable("C09 offline original crossed installed authority")
        for original in (claim, terminal):
            if original is None:
                continue
            payload = offline_tick_to_wire_v1(original)
            signature = payload.pop("signature")
            expected = hmac.new(self._key, canonical_serialize(payload).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise AuthorityUnavailable("C09 offline signed original differs")
        return binding, claim, terminal

    def verify_life_journal_row_v1(self, journal, row):
        from .d11_life_journal_v1 import decode_life_row_v1
        from ..runtime.d11_life_contract_v1 import life_to_wire_v1
        binding, claim, terminal = decode_life_row_v1(journal, row)
        if (self.kind != "life" or binding.namespace != self.namespace
                or binding.authority_namespace != self.authority_namespace or binding.authority_id != self.authority_id
                or binding.installation_id != self.installation_id
                or any(getattr(binding, name) != value for name, value in self.life_build.items())):
            raise AuthorityUnavailable("C09 Life original differs from installed authority/build")
        for original in (claim, terminal):
            if original is None:
                continue
            payload = life_to_wire_v1(original)
            signature = payload.pop("signature")
            expected = hmac.new(self._key, canonical_serialize(payload).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise AuthorityUnavailable("C09 Life signed original differs")
        return binding, claim, terminal

    def verify_installed_terminal(self, binding, claim, terminal):
        from .internal_work_contract import InternalWorkTerminalV2, claim_internal_work_v1, canonical_json
        from .internal_work_service import AuthorityInternalWorkService
        if (self.kind != "internal" or type(terminal) is not InternalWorkTerminalV2
                or terminal.status == "unknown" or binding.algorithm_ref != self.installed_algorithm_id
                or binding.algorithm_build_digest != self.installed_build_digest
                or claim != claim_internal_work_v1(binding) or terminal.binding_digest != binding.binding_digest
                or terminal.algorithm_id != binding.algorithm_ref or terminal.build_fingerprint != binding.algorithm_build_digest
                or terminal.input_digest != binding.input_digest):
            return False
        payload = asdict(terminal)
        payload.pop("execution_signature")
        expected = hmac.new(self._key, canonical_json(payload).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, terminal.execution_signature):
            return False
        if terminal.status == "failed":
            return True
        if self.installed_algorithm_id == "d06.association_activation.v3":
            from .installed_c04_executor_v3 import decode_completed_c04_output_v3
            decode_completed_c04_output_v3(binding, terminal)
        payload = AuthorityInternalWorkService._component_payload(binding, terminal).encode()
        return (terminal.component_receipt_ref == "internal-work:component:" + binding.binding_digest
            and hmac.compare_digest(hashlib.sha256(payload).hexdigest(), terminal.component_receipt_digest)
            and hmac.compare_digest(hmac.new(self._key, payload, hashlib.sha256).hexdigest(), terminal.component_receipt_signature))
