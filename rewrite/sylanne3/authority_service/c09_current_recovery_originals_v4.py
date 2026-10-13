"""Installer-bound C09 facts reader over frozen Authority and Graph originals."""

from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2

from contextlib import contextmanager, closing
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from ..graph_store import GraphStore
    from ..runtime.issuers import D02ResourceIssuer
    from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
    from .internal_work_service import AuthorityInternalWorkService

from ..runtime.c09_sanitized_recovery_extractor_v4 import (
    C09RecoveryAnchorOriginalV4, C09RecoveryFactsHold,
)
from ..runtime.c09_storage_rebase_contract_v1 import (
    SanitizedExecutionFactV4, SanitizedUnknownFactV4,
)
from ..runtime_contracts import NamespaceId, canonical_digest
from .contract import AuthorityUnavailable, JournalHead
from .v2_contract import PendingMutationV2, decode_bytes
from .v2_fence_store import AuthorityV2FenceStore


def _plain_digest(value: str) -> str:
    return value.removeprefix("sha256:")


class InstalledC09RecoveryOriginalsV4:
    """One installed reader; Core supplies its already verified old-chain rows.

    Construction binds live services, never caller-supplied facts. Every read
    runs inside the Core-owned freeze and one business SQLite snapshot.
    """

    def __init__(self, *, core, closure, graph: GraphStore,
                 namespace_id: NamespaceId, resource_issuer: D02ResourceIssuer,
                 body_authority: D02BodyQuoteAuthority,
                 internal_services: dict[str, AuthorityInternalWorkService], budget_job_issuer=None):
        from .core import AuthorityServiceCore
        from .erasure_closure_inventory import AuthorityErasureClosureInventory
        from .internal_work_service import AuthorityInternalWorkService
        from ..graph_store import GraphStore
        from ..runtime.issuers import D02ResourceIssuer
        from ..domains.d02.body_quote_original import D02BodyQuoteAuthority

        if (type(core) is not AuthorityServiceCore
                or type(closure) is not AuthorityErasureClosureInventory
                or closure.core is not core
                or not isinstance(graph, GraphStore)
                or type(namespace_id) is not NamespaceId
                or type(resource_issuer) is not D02ResourceIssuer
                or type(body_authority) is not D02BodyQuoteAuthority
                or type(internal_services) is not dict
                or any(type(service) is not AuthorityInternalWorkService
                       or not service.installed_runtime_verified
                       or service.journal.namespace != closure.namespace
                       or service.journal.path.resolve() != closure.execution.path.resolve()
                       or algorithm not in service.installed_builds
                       for algorithm, service in internal_services.items())):
            raise C09RecoveryFactsHold(("installed_readers",))
        self.core, self.closure, self.graph = core, closure, graph
        self.namespace_id = namespace_id
        self.resource_issuer = resource_issuer
        from ..runtime.issuers import D11BudgetJobIssuer
        if budget_job_issuer is not None and (type(budget_job_issuer) is not D11BudgetJobIssuer
                or budget_job_issuer.resource_issuer is not resource_issuer):
            raise C09RecoveryFactsHold(("installed_life_budget_job_issuer",))
        self.budget_job_issuer = budget_job_issuer
        self.body_authority = body_authority
        self.internal_services = dict(internal_services)
        with graph._lock:
            graph._ensure_open()
            row = graph._db.execute("PRAGMA database_list").fetchone()
            if row is None or not row[2]:
                raise C09RecoveryFactsHold(("graph_path",))
            self.graph_path = Path(row[2]).resolve(strict=True)
        self._snapshot = None
        self._original_cache = None
        self._model_cache = None
        self._contact_registry = graph._registry
        self._contact_control = core._c09_storage_reader_v1
        self._contact_finish_scope = None
        self._life_completed_scope = None
        from .c09_contact_finish_original_v1 import _register_contact_finish_port_v1
        _register_contact_finish_port_v1(self)

    @contextmanager
    def freeze_verified_originals_v4(self, *, seal, old, rows,
                                     verifier_commitment: str):
        if self._snapshot is not None or old.path.resolve() != self.closure.execution.path.resolve():
            raise C09RecoveryFactsHold(("installed_freeze",))
        with self.graph._lock:
            graph_path = self.graph_path
            if self.graph._db is not None and not getattr(self.graph, "_closed", False):
                path_row = self.graph._db.execute("PRAGMA database_list").fetchone()
                if path_row is None or Path(path_row[2]).resolve() != graph_path:
                    raise C09RecoveryFactsHold(("graph_path",))
        uri = "file:" + quote(Path(graph_path).resolve().as_posix(), safe="/:") + "?mode=ro"
        try:
            with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as business:
                business.execute("PRAGMA query_only=ON")
                business.execute("BEGIN")
                # Materialize the WAL read snapshot before reading Core.
                business.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
                with self.core._tx() as control:
                    if self.core._id(control) != seal.authority_id:
                        raise C09RecoveryFactsHold(("authority_identity",))
                    self._snapshot = (seal, old, rows, verifier_commitment,
                                      business, control)
                    try:
                        yield self
                    finally:
                        from .c09_contact_disposition_v1 import _revoke_contact_carriers_v1
                        _revoke_contact_carriers_v1(self)
                        self._snapshot = None
                        self._original_cache = None
                        self._model_cache = None
                business.execute("ROLLBACK")
        except sqlite3.Error as exc:
            raise C09RecoveryFactsHold(("business_snapshot",)) from exc

    def _current(self, namespace: str, operation_id: str):
        if self._snapshot is None:
            raise C09RecoveryFactsHold(("installed_freeze",))
        seal = self._snapshot[0]
        if (namespace, operation_id) != (seal.namespace, seal.operation_id):
            raise C09RecoveryFactsHold(("operation_identity",))
        return self._snapshot

    def _installed_verifier(self, kind, namespace):
        registries = {"numeric": self.core._execution_redaction_d04_numeric_services_v3,
            "series": self.core._execution_redaction_d04_series_services_v1,
            "authored_root": self.core._execution_redaction_d04_root_services_v3,
            "offline_tick": self.core._execution_redaction_d11_offline_services_v1,
            "life": self.core._execution_redaction_d11_life_services_v1}
        return registries[kind].get(namespace)

    def read_current_anchor_v4(self, *, namespace, operation_id):
        seal, _old, _rows, verifier, _business, _control = self._current(
            namespace, operation_id)
        return C09RecoveryAnchorOriginalV4(
            seal.authority_id, seal.installation_id, namespace, operation_id,
            seal.execution_digest, verifier)

    def _originals(self, namespace: str, operation_id: str):
        from .internal_work_contract import InternalWorkTerminalProofV1
        if self._original_cache is not None:
            self._current(namespace, operation_id)
            return self._original_cache
        seal, old, rows, _verifier, _business, control = self._current(
            namespace, operation_id)
        claims = {}
        terminals = {}
        phases = {}
        row_by_mutation = {}
        for row in rows:
            from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_ENTRY_PREFIX
            if row[4].startswith(LIFE_ENTRY_PREFIX):
                continue
            from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_ENTRY_PREFIX
            if row[4].startswith(OFFLINE_ENTRY_PREFIX):
                continue
            from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_ENTRY_PREFIX
            if row[4].startswith(SERIES_ENTRY_PREFIX):
                continue
            from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3
            if row[4].startswith(ROOT_ENTRY_PREFIX_V3):
                continue
            from .d04_numeric_journal_v3 import ENTRY_PREFIX
            if row[4].startswith(ENTRY_PREFIX):
                # Dedicated numeric originals are read below with their own
                # installed verifier, never decoded as dispatch or C04 Body work.
                continue
            if row[4].startswith(b'{"binding":'):
                binding, claim, terminal = old._decode_internal_row(row)
                if binding.namespace != namespace:
                    raise C09RecoveryFactsHold(("internal_namespace",))
                if terminal is None:
                    claims[binding.binding_digest] = (binding, claim, row)
                else:
                    terminals[binding.binding_digest] = (binding, claim, terminal, row)
                continue
            pending = decode_bytes(row[4])
            if type(pending) is not PendingMutationV2 or pending.permit.namespace != namespace:
                raise C09RecoveryFactsHold(("dispatch_original",))
            effect_id = pending.permit.effect_id
            if effect_id is None:
                raise C09RecoveryFactsHold(("dispatch_effect",))
            if pending.mutation_id in row_by_mutation:
                raise C09RecoveryFactsHold(("duplicate_dispatch_mutation",))
            phases[effect_id] = pending
            row_by_mutation[pending.mutation_id] = row
        for row in control.execute(
                "SELECT mutation_id,state FROM authority_v2_mutations "
                "WHERE namespace=? AND mutation_kind='execution'",
                (namespace,)):
            if row[1] == "pending" or (row[1] == "committed"
                                       and row[0] not in row_by_mutation):
                raise C09RecoveryFactsHold(("execution_mutation_completeness",))
        indexed_effects = tuple(control.execute(
            "SELECT effect_id,state FROM authority_effects WHERE namespace=?",
            (namespace,)))
        historical = set()
        if control.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
            historical = {r[0] for r in control.execute("SELECT item_id FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='execution_id'",(namespace,))}
        if ({effect for effect, _ in indexed_effects if effect not in historical} != set(phases)
                or any(state != "unresolved" for effect, state in indexed_effects
                       if effect in phases
                       if phases[effect].phase == "claimed" or
                       (phases[effect].phase == "observed" and
                        phases[effect].platform_observation.outcome in
                        {"unknown", "handed_off"}))):
            raise C09RecoveryFactsHold(("execution_rights",))
        proofs = {}
        for key, (binding, claim, terminal, terminal_row) in terminals.items():
            prior = claims.get(key)
            service = self.internal_services.get(binding.algorithm_ref)
            if (prior is None or prior[:2] != (binding, claim)
                    or service is None):
                raise C09RecoveryFactsHold(("internal_terminal_pair",))
            claim_row = prior[2]
            claim_append = old._internal_append_receipt(claim_row, binding, "claim")
            terminal_append = old._internal_append_receipt(
                terminal_row, binding, "terminal")
            proof = InternalWorkTerminalProofV1(
                binding, claim, terminal, claim_append.receipt_ref,
                claim_append.content_digest, terminal_append.receipt_ref,
                terminal_append.content_digest,
                JournalHead(old.journal_id, terminal_row[0], terminal_row[6]))
            if terminal.status != "unknown" and service.verify_installed_terminal(
                    binding, claim, terminal) is not True:
                raise C09RecoveryFactsHold(("internal_signature",))
            proofs[binding.operation_id] = (proof, service)
        self._original_cache = (seal, claims, terminals, proofs, phases,
                                row_by_mutation, control)
        return self._original_cache

    def _life_originals(self, namespace, operation_id):
        from .c09_life_recovery_originals_v1 import read_life_recovery_originals_v1
        _, old, rows, _, business, control = self._current(namespace, operation_id)
        service = self._installed_verifier("life", namespace)
        return read_life_recovery_originals_v1(business=business, core_db=control,
            journal=old, rows=rows, service=service, namespace=namespace)

    def _offline_originals(self, namespace, operation_id):
        from .c09_offline_recovery_originals_v1 import read_offline_recovery_originals_v1
        _, old, rows, _, business, control = self._current(namespace, operation_id)
        service = self._installed_verifier("offline_tick", namespace)
        return read_offline_recovery_originals_v1(business=business, core_db=control,
            journal=old, rows=rows, service=service, namespace=namespace)

    def _numeric_originals(self, namespace, operation_id):
        seal, old, rows, _, business, _ = self._current(namespace, operation_id)
        from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3
        from ..runtime.d04_numeric_cost_v3 import read_d04_numeric_prepared_v3
        from ..runtime.d04_numeric_accounting_prepared_v3 import read_numeric_accounting_prepared_v3
        service = self._installed_verifier("numeric", namespace)
        originals = {}
        for row in rows:
            if not row[4].startswith(ENTRY_PREFIX):
                continue
            if service is None:
                raise C09RecoveryFactsHold(("numeric_installed_verifier",))
            binding, claim, measurement = decode_numeric_row_v3(old, row)
            verified_binding, verified_claim, terminal = service.verify_numeric_journal_row_v3(old, row)
            body = read_d04_numeric_prepared_v3(business, self.namespace_id, binding.operation_id)
            prepared = read_numeric_accounting_prepared_v3(business, self.namespace_id,
                binding.operation_id, issuer=self.resource_issuer)
            if ((verified_binding, verified_claim) != (binding, claim)
                    or prepared is None or prepared.binding != binding
                    or (body is not None and (body.binding != binding or body.digest != prepared.prepared_digest))):
                raise C09RecoveryFactsHold(("numeric_original_preparation",))
            prior = originals.get(binding.execution_id)
            if measurement is None:
                if prior is not None:
                    raise C09RecoveryFactsHold(("numeric_duplicate_claim",))
                originals[binding.execution_id] = (binding, claim, None, prepared)
            elif prior is None or prior[:2] != (binding, claim) or prior[2] is not None:
                raise C09RecoveryFactsHold(("numeric_terminal_pair",))
            else:
                originals[binding.execution_id] = (binding, claim, terminal, prepared)
        return tuple(originals[key] for key in sorted(originals))

    def _series_originals(self, namespace, operation_id):
        from .d04_series_journal_v1 import ENTRY_PREFIX, decode_series_row_v1
        from ..runtime.d04_series_accounting_original_v1 import read_series_accounting_original_v1
        _seal, old, rows, _, business, _ = self._current(namespace, operation_id)
        service = self._installed_verifier("series", namespace)
        originals = {}
        for row in rows:
            if not row[4].startswith(ENTRY_PREFIX):
                continue
            if service is None:
                raise C09RecoveryFactsHold(("series_installed_verifier",))
            binding, claim, measured = decode_series_row_v1(old, row)
            verified_binding, verified_claim, terminal = service.verify_series_journal_row_v1(old, row)
            prepared = read_series_accounting_original_v1(business, self.namespace_id,
                binding.numeric.operation_id, issuer=self.resource_issuer)
            if ((verified_binding, verified_claim) != (binding, claim)
                    or prepared is None or prepared.binding != binding):
                raise C09RecoveryFactsHold(("series_original_accounting_preparation",))
            key = binding.numeric.execution_id
            prior = originals.get(key)
            if measured is None:
                if prior is not None:
                    raise C09RecoveryFactsHold(("series_duplicate_claim",))
                originals[key] = (binding, claim, None, prepared)
            elif prior is None or prior[:2] != (binding, claim) or prior[2] is not None:
                raise C09RecoveryFactsHold(("series_terminal_pair",))
            else:
                originals[key] = (binding, claim, terminal, prepared)
        return tuple(originals[key] for key in sorted(originals))

    def _root_originals(self, namespace, operation_id):
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3, decode_root_execution_row_v3
        from ..runtime.d04_root_accounting_prepared_v3 import read_root_accounting_prepared_v3
        from ..runtime.d04_root_execution_v3 import read_root_prepared_v3
        _seal, old, rows, _, business, _ = self._current(namespace, operation_id)
        service = self._installed_verifier("authored_root", namespace)
        originals = {}
        for row in rows:
            if not row[4].startswith(ROOT_ENTRY_PREFIX_V3):
                continue
            if service is None:
                raise C09RecoveryFactsHold(("root_installed_verifier",))
            binding, claim, measurement = decode_root_execution_row_v3(old, row)
            verified_binding, verified_claim, terminal = service.verify_root_journal_row_v3(old, row)
            saved = read_root_accounting_prepared_v3(business, self.namespace_id, binding.operation_id,
                resource_issuer=service.resource_issuer, budget_issuer=service.budget_issuer)
            body = read_root_prepared_v3(business, self.namespace_id, binding.operation_id)
            if (saved is None or (verified_binding, verified_claim) != (binding, claim)
                    or (body is not None and (body.binding != binding or body.digest != saved[0]["prepared_digest"]))):
                raise C09RecoveryFactsHold(("root_original_accounting_preparation",))
            prepared = _RootAccountingSourceV1(binding=binding, **{name: saved[0][name] for name in
                ("prepared_digest", "quote_payload_json", "reserve_receipt_json")})
            prior = originals.get(binding.execution_id)
            if measurement is None:
                if prior is not None:
                    raise C09RecoveryFactsHold(("root_duplicate_claim",))
                originals[binding.execution_id] = (binding, claim, None, prepared)
            elif prior is None or prior[:2] != (binding, claim) or prior[2] is not None:
                raise C09RecoveryFactsHold(("root_terminal_pair",))
            else:
                originals[binding.execution_id] = (binding, claim, terminal, prepared)
        return tuple(originals[key] for key in sorted(originals))

    def read_current_execution_originals_v4(self, *, namespace, operation_id):
        (_seal, claims, terminals, _proofs, phases, row_by_mutation,
         control) = self._originals(namespace, operation_id)
        facts = []
        for key, (binding, _claim, _row) in claims.items():
            terminal = terminals.get(key)
            if terminal is None or terminal[2].status == "unknown":
                # This is the commitment of the Core-authenticated claim, not
                # a completed component or a fabricated zero CPU terminal.
                facts.append(SanitizedExecutionFactV4(binding.execution_id,
                    binding.input_digest, None, None,
                    canonical_digest((_seal.seal_digest, _row[6])), "unknown", True))
                continue
            value = terminal[2]
            facts.append(SanitizedExecutionFactV4(
                binding.execution_id, binding.input_digest,
                value.result_digest if value.status == "completed" else None,
                canonical_digest(value), value.execution_signature,
                value.status, True))
        for effect_id, pending in phases.items():
            row = row_by_mutation[pending.mutation_id]
            mutation = AuthorityV2FenceStore.mutation_locked(
                control, pending.mutation_id)
            if mutation is None:
                raise C09RecoveryFactsHold(("dispatch_mutation",))
            kind, stored, receipt, _updated = (
                AuthorityV2FenceStore._decode_mutation_row(mutation))
            if kind != "execution" or stored != pending or receipt is None:
                raise C09RecoveryFactsHold(("dispatch_mutation",))
            if pending.phase == "prepared":
                status = "pending"
            elif pending.phase == "claimed":
                status = "unknown"
            else:
                outcome = pending.platform_observation.outcome
                status = ("failed" if outcome == "failed_before_acceptance"
                          else "unknown" if outcome in {"unknown", "handed_off"}
                          else "completed")
            facts.append(SanitizedExecutionFactV4(
                effect_id, _plain_digest(pending.permit.command_digest),
                (canonical_digest(pending.platform_observation)
                 if pending.phase == "observed" else None),
                _plain_digest(row[6]) if pending.phase == "observed" else None,
                canonical_digest(receipt), status, status != "pending"))
        for binding, claim, terminal, _prepared in self._numeric_originals(namespace, operation_id):
            facts.append(SanitizedExecutionFactV4(binding.execution_id, binding.input_digest,
                None if terminal is None else terminal.measurement.output_original_digest,
                None if terminal is None else terminal.digest,
                canonical_digest(claim.signature if terminal is None else terminal.signature),
                "unknown" if terminal is None else terminal.measurement.status, True))
        for series, claim, terminal, _prepared in self._series_originals(namespace, operation_id):
            binding = series.numeric
            facts.append(SanitizedExecutionFactV4(binding.execution_id, binding.input_digest,
                None if terminal is None else terminal.measurement.chunk_math_digest,
                None if terminal is None else terminal.digest,
                canonical_digest(claim.signature if terminal is None else terminal.signature),
                "unknown" if terminal is None else "completed" if terminal.measurement.status == "chunk_completed" else "failed", True))
        for binding, claim, terminal, _prepared in self._root_originals(namespace, operation_id):
            facts.append(SanitizedExecutionFactV4(binding.execution_id, binding.input_digest,
                None if terminal is None else terminal.measurement.artifact_digest,
                None if terminal is None else terminal.digest,
                canonical_digest(claim.signature if terminal is None else terminal.signature),
                "unknown" if terminal is None else terminal.measurement.status, True))
        for original in self._model_originals(namespace, operation_id):
            facts.append(SanitizedExecutionFactV4(original.call_id, original.request_digest,
                original.observation_digest_or_none, original.terminal_digest_or_none,
                original.original_digest, "completed" if original.provider_state == "observed" else
                "pending" if original.provider_state == "prepared" else "unknown", True))
        for binding, claim, terminal, _, _ in self._life_originals(namespace, operation_id):
            facts.append(SanitizedExecutionFactV4(binding.execution_id, binding.input_digest,
                None if terminal is None else terminal.payload.artifact_digest,
                None if terminal is None else _plain_digest(terminal.terminal_digest),
                claim.payload.signature if terminal is None else terminal.payload.signature,
                "unknown" if terminal is None else terminal.status, True))
        for binding, claim, terminal, _, _ in self._offline_originals(namespace, operation_id):
            facts.append(SanitizedExecutionFactV4(binding.execution_id, binding.input_digest,
                None if terminal is None or terminal.payload.result is None else canonical_digest(terminal.payload.result),
                None if terminal is None else _plain_digest(terminal.terminal_digest),
                claim.payload.signature if terminal is None else terminal.payload.signature,
                "unknown" if terminal is None else terminal.status, True))
        return tuple(sorted(facts, key=lambda item: item.execution_id))

    def _model_originals(self, namespace, operation_id):
        seal, _old, _rows, _, business, control = self._current(namespace, operation_id)
        if self._model_cache is None:
            from .c09_model_budget_original_v1 import capture_frozen_model_budget_originals_v1
            self._model_cache = capture_frozen_model_budget_originals_v1(core_db=control,
                business=business, namespace_id=self.namespace_id, seal=seal, resource_issuer=self.resource_issuer,
                meter=current_c09_sql_meter_v2(), require_existing=getattr(self, "_completed_core", False),
                budget_job_issuer=self.budget_job_issuer)
        return self._model_cache

    def read_current_d02_originals_v4(self, *, namespace, operation_id):
        from ..runtime.c09_d02_c04_recovery_reader_v4 import (
            read_c04_d02_recovery_fact_connection_v4,
        )
        (_seal, _claims, _terminals, proofs, _phases, _rows,
         _control) = self._originals(namespace, operation_id)
        business = self._snapshot[4]
        result = []
        for c04_operation, (proof, service) in proofs.items():
            if proof.terminal.status == "completed":
                result.append(read_c04_d02_recovery_fact_connection_v4(
                    business, namespace=self.namespace_id,
                    operation_id=c04_operation, issuer=self.resource_issuer,
                    body_authority=self.body_authority, authority=service,
                    prepared_proof=proof))
        return tuple(sorted(result, key=lambda item: item.quote_id))

    def read_current_d11_originals_v4(self, *, namespace, operation_id):
        from ..runtime.c09_d11_c04_recovery_reader_v4 import (
            read_c04_d11_recovery_fact_connection_v4,
        )
        (_seal, _claims, _terminals, proofs, _phases, _rows,
         _control) = self._originals(namespace, operation_id)
        business = self._snapshot[4]
        result = [read_c04_d11_recovery_fact_connection_v4(
            business, namespace=self.namespace_id, operation_id=c04_operation,
            issuer=self.resource_issuer, authority=service,
            prepared_proof=proof)
            for c04_operation, (proof, service) in proofs.items()
            if proof.terminal.status in {"completed", "failed"}]
        from ..runtime.d04_numeric_cost_v3 import read_d04_numeric_cost_original_v3
        from ..runtime.c09_storage_rebase_contract_v1 import SanitizedD11FactV4
        for binding, _claim, terminal, _prepared in self._numeric_originals(namespace, operation_id):
            if terminal is None:
                continue
            cost = read_d04_numeric_cost_original_v3(business, self.namespace_id, binding.operation_id)
            reservation = business.execute("SELECT digest,ceiling_json,state,actual_json FROM "
                "runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
            if (cost is None or cost.terminal_digest != terminal.digest
                    or cost.binding_digest != binding.digest or reservation is None
                    or reservation[0] != binding.reservation_digest
                    or reservation[2] not in {"settled", "overrun"}
                    or __import__('json').loads(reservation[1]) != {"cpu_ms": binding.cpu_ceiling_ms}
                    or __import__('json').loads(reservation[3]) != {"cpu_ms": terminal.measurement.actual_cpu_ms}):
                raise C09RecoveryFactsHold(("numeric_original_cpu_accounting",))
            amount = terminal.measurement.actual_cpu_ms
            result.append(SanitizedD11FactV4("d04-numeric-cost:" + binding.digest[:48],
                binding.parent_budget_lease_ref, binding.reservation_operation_id,
                binding.cpu_ceiling_ms, amount, amount, 0, max(0, amount - binding.cpu_ceiling_ms)))
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        for binding, _claim, terminal, _prepared in self._root_originals(namespace, operation_id):
            if terminal is None:
                continue
            original = read_d04_original_v3(business, self.namespace_id, "root_cost", binding.operation_id)
            reservation = business.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
            amount = terminal.measurement.actual_cpu_ms
            if (original is None or original[0]["terminal_digest"] != terminal.digest
                    or original[0]["binding_digest"] != binding.digest
                    or (original[0]["actual_cpu_ns"], original[0]["actual_cpu_ms"]) != (terminal.measurement.actual_cpu_ns, amount)
                    or reservation is None or reservation[0] != binding.reservation_digest
                    or reservation[2] not in {"settled", "overrun"}
                    or __import__('json').loads(reservation[1]) != {"thread_cpu_ms": binding.cpu_ceiling_ms}
                    or __import__('json').loads(reservation[3]) != {"thread_cpu_ms": amount}):
                raise C09RecoveryFactsHold(("root_original_cpu_accounting",))
            cost_write = __import__('json').loads(original[0]["graph_write_json"])
            cost_id = cost_write["value"]["settlement_id"]
            result.append(SanitizedD11FactV4(cost_id, binding.parent_budget_lease_ref, binding.reservation_operation_id,
                binding.cpu_ceiling_ms, amount, amount, 0, max(0, amount - binding.cpu_ceiling_ms), "thread_cpu_ms"))
        from .c09_model_budget_original_v1 import model_unit_fact_v4
        from ..runtime.d04_series_accounting_original_v1 import read_series_cpu_cost_original_v1
        for series, _claim, terminal, _prepared in self._series_originals(namespace, operation_id):
            if terminal is None:
                continue
            binding = series.numeric
            cost = read_series_cpu_cost_original_v1(business, self.namespace_id, series, terminal)
            reservation = business.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (binding.parent_budget_lease_ref, binding.reservation_operation_id)).fetchone()
            amount = terminal.measurement.actual_cpu_ms
            if (cost is None or reservation is None or reservation[0] != binding.reservation_digest
                    or reservation[2] not in {"settled", "overrun"}
                    or __import__('json').loads(reservation[1]) != {"cpu_ms": binding.cpu_ceiling_ms}
                    or __import__('json').loads(reservation[3]) != {"cpu_ms": amount}):
                raise C09RecoveryFactsHold(("series_original_cpu_accounting",))
            result.append(SanitizedD11FactV4("d04-series-cost:" + canonical_digest((series.root_digest, series.start_step_index))[:48],
                binding.parent_budget_lease_ref, binding.reservation_operation_id,
                binding.cpu_ceiling_ms, amount, amount, 0, max(0, amount - binding.cpu_ceiling_ms), "thread_cpu_ms"))
        for original in self._model_originals(namespace, operation_id):
            result.extend(model_unit_fact_v4(original, unit) for unit in original.units if unit.actual_or_none is not None)
        result.extend(fact for _, _, _, _, fact in self._offline_originals(namespace, operation_id) if fact is not None)
        result.extend(fact for _, _, _, _, fact in self._life_originals(namespace, operation_id) if fact is not None)
        return tuple(sorted(result, key=lambda item: item.settlement_id))

    def read_current_unknown_originals_v4(self, *, namespace, operation_id):
        (_seal, _claims, _terminals, _proofs, phases, _rows,
         control) = self._originals(namespace, operation_id)
        facts = []
        from ..runtime.c09_internal_unknown_originals_v4 import read_internal_unknown_original_v4
        from ..runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        business = self._snapshot[4]
        for key, (binding, _claim, _row) in _claims.items():
            terminal = _terminals.get(key)
            if terminal is not None and terminal[2].status != "unknown":
                continue
            prepared = read_c04_internal_work_prepared_v1(business, self.namespace_id, binding.operation_id)
            if prepared is None or prepared.binding != binding:
                raise C09RecoveryFactsHold(("internal_unknown_original_preparation",))
            facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                authority_namespace=namespace, binding=binding, prepared=prepared, issuer=self.resource_issuer,
                body_authority=self.body_authority))
        for binding, _claim, terminal, prepared in self._numeric_originals(namespace, operation_id):
            if terminal is None:
                facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                    authority_namespace=namespace, binding=binding, prepared=prepared,
                    issuer=self.resource_issuer, numeric=True))
        for binding, _claim, terminal, prepared in self._root_originals(namespace, operation_id):
            if terminal is None:
                facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                    authority_namespace=namespace, binding=binding, prepared=prepared,
                    issuer=self.resource_issuer, authored_root=True))
        for series, _claim, terminal, prepared in self._series_originals(namespace, operation_id):
            if terminal is None:
                facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                    authority_namespace=namespace, binding=series.numeric, prepared=prepared,
                    issuer=self.resource_issuer, numeric=True))
        for binding, _claim, terminal, prepared, _ in self._life_originals(namespace, operation_id):
            if terminal is None or terminal.status == "unknown":
                facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                    authority_namespace=namespace, binding=binding, prepared=prepared,
                    issuer=self.resource_issuer, numeric=True, life=True))
        for binding, _claim, terminal, prepared, _ in self._offline_originals(namespace, operation_id):
            if terminal is None or terminal.status == "unknown":
                facts.append(read_internal_unknown_original_v4(business, namespace=self.namespace_id,
                    authority_namespace=namespace, binding=binding, prepared=prepared,
                    issuer=self.resource_issuer, numeric=True, offline_tick=True))
        from ..runtime_journal import RecoveryConstraintFootprint
        for original in self._model_originals(namespace, operation_id):
            if original.provider_state not in {"dispatch_started", "unknown"}:
                continue
            # Budget amounts are deliberately absent from the unitless legacy
            # footprint. Every unit is retained in the fixed bound original.
            footprint = RecoveryConstraintFootprint(namespace, original.job_id, original.call_id,
                external_idempotency_ref=original.call_id,
                external_query_ref=original.provider_query_ref_or_none,
                conflict_keys=tuple(sorted({"model-call:" + original.call_id, "model-job:" + original.job_id,
                    "model-budget:" + original.parent_budget_id})))
            facts.append(SanitizedUnknownFactV4(original.call_id, original.dispatch_generation,
                original.provider_query_ref_or_none, 0, (), footprint))
        for effect_id, pending in phases.items():
            if pending.phase == "prepared":
                continue
            if pending.phase == "observed" and pending.platform_observation.outcome \
                    not in {"unknown", "handed_off"}:
                continue
            row = AuthorityV2FenceStore.mutation_locked(
                control, pending.mutation_id)
            if row is None:
                raise C09RecoveryFactsHold(("unknown_mutation",))
            kind, saved, receipt, _updated = (
                AuthorityV2FenceStore._decode_mutation_row(row))
            footprint = AuthorityV2FenceStore._decode_footprint(saved, row[11])
            if (kind != "execution" or receipt is None or saved != pending
                    or footprint.effect_id != effect_id
                    or footprint.namespace != namespace):
                raise C09RecoveryFactsHold(("unknown_footprint",))
            facts.append(SanitizedUnknownFactV4(
                effect_id, pending.permit.generation,
                footprint.external_query_ref,
                sum(item.occupied for item in footprint.quota_occupancies),
                tuple(sorted([(item.parent_budget_ref, item.pending_amount,
                               item.upper_bound) for item in footprint.budgets],
                             key=lambda item: item[0])), footprint))
        return tuple(sorted(facts, key=lambda item: item.execution_id))

    def read_current_graph_originals_v4(self, *, namespace, operation_id):
        seal, _old, _rows, verifier, business, control = self._current(namespace, operation_id)
        from ..runtime.c09_graph_originals_read_v4 import (
            read_current_graph_originals_v4,
        )
        facts = read_current_graph_originals_v4(business, self.namespace_id, operation_id)
        from .c09_contact_finish_original_v1 import capture_contact_finish_originals_v1, contact_graph_fact_v1, contact_finish_inventory_fact_v1, _issue_contact_finish_scope_v1, _revoke_contact_finish_scope_v1
        _revoke_contact_finish_scope_v1(self)
        originals = capture_contact_finish_originals_v1(core_db=control, business=business,
            namespace_id=self.namespace_id, seal=seal, verifier_commitment=verifier,
            registry=self._contact_registry, graph_facts=facts,
            require_existing=getattr(self, '_completed_core', False), storage_reader=self._contact_control)
        replacements = {item.business_operation_id: contact_graph_fact_v1(item) for item in originals}
        self._contact_finish_scope = _issue_contact_finish_scope_v1(self, originals) if originals else None
        if any(f.operation_id.startswith('c09-contact-finish-inventory:') for f in facts):
            raise AuthorityUnavailable('C09 Graph business operation uses reserved Contact inventory identity')
        issued = tuple(o for o in originals if o.operation_id == seal.operation_id)
        inventory = () if not issued else (contact_finish_inventory_fact_v1(seal.operation_id, issued),)
        from .c09_life_completed_archive_v1 import (
            capture_and_store_completed_life_archive_v1, life_inventory_fact_v1,
            INVENTORY_PREFIX as LIFE_INVENTORY_PREFIX)
        if any(f.operation_id.startswith(LIFE_INVENTORY_PREFIX) for f in facts):
            raise AuthorityUnavailable('C09 Graph business operation uses reserved Life inventory identity')
        life_archive = capture_and_store_completed_life_archive_v1(self,
            namespace=namespace, operation_id=operation_id,
            require_existing=getattr(self, '_completed_core', False))
        life_inventory = (life_inventory_fact_v1(life_archive),)
        return tuple(sorted((*tuple(replacements.get(fact.operation_id, fact) for fact in facts), *inventory, *life_inventory),
                            key=lambda f: f.operation_id))


__all__ = ["InstalledC09RecoveryOriginalsV4"]


@dataclass(frozen=True, slots=True)
class _RootAccountingSourceV1:
    binding: object
    prepared_digest: str
    quote_payload_json: str
    reserve_receipt_json: str


class ConnectionC09RecoveryOriginalsV4(InstalledC09RecoveryOriginalsV4):
    """The same five-family reader on pre-Core qualified maintenance SQL."""
    def __init__(self, *, config, control, core_db, business_db, execution_reader, rows):
        from .c09_execution_connection_v1 import C09ExecutionOriginalsConnectionV1
        from .c09_installed_original_verifiers_v1 import InstalledC09OriginalVerifierV1
        from .c09_connection_state_v1 import authority_id_in_tx_v1
        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES
        from .d04_numeric_journal_v3 import ENTRY_PREFIX as NUMERIC
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3 as ROOT
        from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE
        from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE
        if (type(execution_reader) is not C09ExecutionOriginalsConnectionV1
                or not core_db.in_transaction or not business_db.in_transaction
                or authority_id_in_tx_v1(core_db) != control.authority_id):
            raise C09RecoveryFactsHold(("actual_connection_composition",))
        context = control.read_verified_current_storage_v1(verify_files=False)
        actual = {"core": core_db, "graph": business_db, "execution": execution_reader._db}
        for role, db in actual.items():
            member = next(m for m in context.manifest["members"] if m["role"] == role)
            if str(Path(db.execute("PRAGMA database_list").fetchone()[2]).resolve()) != member["resolved_path"]:
                raise C09RecoveryFactsHold(("actual_selected_source_connections",))
            control.verify_member_v1(member, prepared=False)
        factory = config.c09_maintenance_factory
        self.namespace_id = factory.namespace
        self.resource_issuer, self.body_authority = factory.resource_issuer, factory.body_authority
        self.budget_job_issuer = getattr(factory, "budget_job_issuer", None)
        self._contact_registry = factory.registry
        self._contact_control = control
        self._contact_finish_scope = None
        self._life_completed_scope = None
        self.internal_services, self._verifiers = {}, {}
        self._snapshot = self._original_cache = self._model_cache = None
        self._connection_material = (core_db, business_db, execution_reader, tuple(rows))
        kinds, algorithms = set(), set()
        for row in rows:
            kind = next((kind for prefix, kind in ((SERIES, "series"), (NUMERIC, "numeric"),
                (ROOT, "authored_root"), (OFFLINE, "offline_tick"), (LIFE, "life")) if row[4].startswith(prefix)), None)
            if kind is not None:
                kinds.add(kind)
            elif row[4].startswith(b'{"binding":'):
                binding, _, _ = execution_reader._decode_internal_row(row)
                algorithms.add(binding.algorithm_ref)
        for kind in sorted(kinds):
            self._verifiers[kind] = InstalledC09OriginalVerifierV1(config=config, control=control,
                core_db=core_db, business_db=business_db, execution_reader=execution_reader, kind=kind)
        for algorithm in sorted(algorithms):
            self.internal_services[algorithm] = InstalledC09OriginalVerifierV1(config=config, control=control,
                core_db=core_db, business_db=business_db, execution_reader=execution_reader,
                kind="internal", algorithm=algorithm)
        from .c09_contact_finish_original_v1 import _register_contact_finish_port_v1
        _register_contact_finish_port_v1(self)

    def _installed_verifier(self, kind, namespace):
        if namespace != self._connection_material[2].namespace:
            raise C09RecoveryFactsHold(("connection_verifier_namespace",))
        return self._verifiers.get(kind)

    @contextmanager
    def freeze_verified_connection_originals_v4(self, *, seal, verifier_commitment):
        core_db, business, old, rows = self._connection_material
        from .c09_connection_state_v1 import authority_id_in_tx_v1
        if (self._snapshot is not None or not business.in_transaction
                or authority_id_in_tx_v1(core_db) != seal.authority_id
                or seal.namespace != old.namespace or seal.execution_journal_id != old.journal_id):
            raise C09RecoveryFactsHold(("actual_connection_snapshot",))
        head, current_rows = old.read_verified_rows_v1()
        if (tuple(current_rows) != rows or (head.seq, head.digest) != (seal.execution_seq, seal.execution_digest)):
            raise C09RecoveryFactsHold(("actual_full_execution_chain",))
        self._snapshot = (seal, old, rows, verifier_commitment, business, core_db)
        try:
            yield self
        finally:
            from .c09_contact_disposition_v1 import _revoke_contact_carriers_v1
            _revoke_contact_carriers_v1(self)
            self._snapshot = self._original_cache = self._model_cache = None

    def verify_execution_rows_v1(self):
        """Authenticate installed identities/signatures before deriving any facts."""
        _, _, old, rows = self._connection_material
        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES
        from .d04_numeric_journal_v3 import ENTRY_PREFIX as NUMERIC
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3 as ROOT
        from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE
        from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE
        signed = []
        for row in rows:
            selected = next(((kind, method) for prefix, kind, method in (
                (SERIES, "series", "verify_series_journal_row_v1"),
                (NUMERIC, "numeric", "verify_numeric_journal_row_v3"),
                (ROOT, "authored_root", "verify_root_journal_row_v3"),
                (OFFLINE, "offline_tick", "verify_offline_tick_journal_row_v1"),
                (LIFE, "life", "verify_life_journal_row_v1")) if row[4].startswith(prefix)), None)
            if selected is not None:
                kind, method = selected
                _, _, terminal = getattr(self._verifiers[kind], method)(old, row)
                if terminal is not None:
                    signed.append(row[2])
            elif row[4].startswith(b'{"binding":'):
                binding, claim, terminal = old._decode_internal_row(row)
                verifier = self.internal_services[binding.algorithm_ref]
                if binding.algorithm_build_digest != verifier.installed_build_digest:
                    raise C09RecoveryFactsHold(("internal_installed_build",))
                if terminal is None:
                    continue
                if terminal.status == "unknown":
                    if (terminal.algorithm_id, terminal.build_fingerprint, terminal.input_digest) != (
                            binding.algorithm_ref, binding.algorithm_build_digest, binding.input_digest):
                        raise C09RecoveryFactsHold(("internal_unknown_identity",))
                    continue
                if not verifier.verify_installed_terminal(binding, claim, terminal):
                    raise C09RecoveryFactsHold(("internal_signature",))
                signed.append(row[2])
        return tuple(signed)
