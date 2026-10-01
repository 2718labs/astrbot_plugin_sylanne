"""Installed D07 preparation/once-only execution and durable original reader.

The service is bound at host startup to W01, the signed installation and the
designated Authority client. Public commands carry intentions and locators;
they cannot supply this service, model responses or purported paid receipts.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
import json
from collections import deque

from ..runtime_contracts import canonical_digest, InstallationGrantV2, VersionedRef
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..graph_types import AtomKey
from .d07_execution_v1 import (
    D07PreparationStageV1, d07_execution_ids_v1, prepare_d07_execution_in_transaction_v1,
    read_prepared_d07_execution_v1, read_d07_original_v1, read_current_original_ref_v1,
    read_registered_simulation_request_v1, decode_d07_execution_original_v1,
    require_current_d07_content_reads_v1, verify_current_d07_preparation_stage_v1,
    read_current_d07_semantic_question_v1,
    resolve_current_d07_semantic_target_v1,
)
from .d07_current_behavior_v1 import D07ExecutionOriginalV1, _json
from .jobs import get_job
from .issuers import D11BudgetJobIssuer


class InstalledD07ExecutionServiceV1:
    installed_executor_ref = "d07.installed-cognition-executor.v1"

    def __init__(self, *, graph, bootstrap, bundle, installation=None, worker=None,
            authority_client=None, client_grant=None, context=None, owner_loop=None):
        from ..graph_coordinator import GraphCoordinator
        from ..host.authority_profile import AdminInstallationBundle
        if type(graph) is not GraphCoordinator or type(bundle) is not AdminInstallationBundle:
            raise TypeError("D07 needs actual W01 and the protected installed model bundle")
        graph._admin(bootstrap)
        self.graph, self.bootstrap, self.bundle = graph, bootstrap, bundle
        self._store = graph._GraphCoordinator__store
        self._db = self._store._db
        self.d11_issuer = graph._GraphCoordinator__d11_issuer
        self.resource_issuer = graph._GraphCoordinator__d02_issuer
        if type(self.d11_issuer) is not D11BudgetJobIssuer:
            raise TypeError("D07 actual signed D11 issuer required")
        self.body_authority = getattr(graph, "_GraphCoordinator__body_quote_authority", None)
        if type(self.body_authority) is not D02BodyQuoteAuthority:
            from ..runtime_context import _installed_body_quote_authority_v1
            self.body_authority = None if installation is None else _installed_body_quote_authority_v1(installation)
        if type(self.body_authority) is not D02BodyQuoteAuthority:
            raise ValueError("D07 actual installation-derived D02 body quote authority is required")
        self.installation, self.worker = installation, worker
        self.authority_client, self.client_grant = authority_client, client_grant
        self.context, self.owner_loop = context, owner_loop
        self._pre_read_cost_facts = {}
        self._pre_read_results = {}
        self._pending = deque()
        self._queued_ids = set()
        self._wake_seen = set()
        self._runner_task = None
        self._closed = False
        self._last_progress = {}
        self._accounting_grants = {}
        self._closed_accounting_requests = {}
        self._discovery_cursor = ""
        self._adapters = {}

    def wake_committed_job_v1(self, job_id):
        """Wake only a durable operation; scheduling carries no execution authority."""
        if self.owner_loop is None or not self.owner_loop.is_running() or self._closed:
            return False
        def enqueue():
            if self._closed or job_id in self._queued_ids:
                return
            if len(self._pending) >= 16:
                # The original remains in runtime_jobs for the next bounded
                # discovery. No work or unknown claim is dropped or reset.
                return
            self._pending.append(job_id)
            self._queued_ids.add(job_id)
            if self._runner_task is None or self._runner_task.done():
                self._runner_task = asyncio.create_task(self._drain_jobs_v1())
        self.owner_loop.call_soon_threadsafe(enqueue)
        return True

    async def _drain_jobs_v1(self):
        while self._pending and not self._closed:
            job_id = self._pending.popleft()
            self._queued_ids.discard(job_id)
            self._wake_seen.add(job_id)
            try:
                def current(graph):
                    from .d07_graph_stages_v1 import read_resume_current_d07_metadata_v1
                    return read_resume_current_d07_metadata_v1(graph, self.bootstrap, self.bundle, job_id=job_id)[0]
                job = await self.worker.call(current)
                self._last_progress[job_id] = await self.execute_current_d07_job_v1(job)
            except asyncio.CancelledError:
                # Host cancellation provides no remote provider-stop proof.
                self._last_progress[job_id] = {"status": "original_execution_unknown", "job_id": job_id}
                raise
            except Exception as exc:
                self._last_progress[job_id] = {"status": "hold", "job_id": job_id, "reason": type(exc).__name__}
        if not self._closed:
            await self.resume_pending_jobs_v1()

    async def resume_pending_jobs_v1(self):
        if self.worker is None or self.owner_loop is not asyncio.get_running_loop() or self._closed:
            return ()
        def discover(graph):
            with self._store._lock:
                rows = self._db.execute("SELECT job_id FROM runtime_jobs AS j WHERE bot_id=? AND persona_id=? AND job_id>? "
                    "AND work_kind IN ('d07.concern','d07.reflection','d07.simulation') "
                    "AND phase IN ('queued','running','completed') AND NOT EXISTS "
                    "(SELECT 1 FROM graph_bundle_operations AS b WHERE b.bot=j.bot_id AND b.persona=j.persona_id AND b.operation_id=j.operation_id) "
                    "ORDER BY job_id LIMIT 17", (*self.bundle.installation_policy.namespace.as_tuple, self._discovery_cursor)).fetchall()
                result = []
                for (ref,) in rows[:16]:
                    if read_prepared_d07_execution_v1(self._db, self.d11_issuer,
                            self.bundle.installation_policy.namespace, ref) is not None:
                        result.append(ref)
                return tuple(result), len(rows) > 16, rows[15][0] if len(rows) > 16 else ""
        refs, more, cursor = await self.worker.call(discover)
        self._discovery_cursor = cursor
        for ref in refs:
            if ref not in self._wake_seen:
                self.wake_committed_job_v1(ref)
        return refs

    async def _recover_local_observation_v1(self, intent, anchor, job_id):
        """Report a retained original response, never invoke a provider again."""
        adapter = self._adapters.get(job_id)
        if adapter is None:
            return None
        from ..authority_service.v2_model_egress_contract import HostObservedModelCompletionV2
        from ..runtime_contracts import canonical_serialize
        try:
            facts = await self.authority_client.model_terminal_fact_v2(self.bundle, self.client_grant, intent=intent)
            record, permit, admission, receipt = facts
            if record.state == "observed" and receipt is not None:
                return receipt
            if (record.state != "dispatch_started" or admission is None
                    or admission.host_incarnation != adapter.host_incarnation):
                return None
            response = adapter.terminal_response(intent.call_id, intent.request_digest, admission.admission_id)
            if response is None or response.status != "completed" or response.result is None:
                return None
            report = HostObservedModelCompletionV2(admission.admission_id, admission.host_incarnation, intent.call_id,
                intent.request_digest, intent.provider_id, intent.model_id, intent.provider_config_digest,
                canonical_serialize(dict(response.result)), tuple(sorted(response.usage.items())),
                tuple(sorted(response.cost.items())), response.provider_call_ref)
            completed, actual_permit, terminal = await self.authority_client.model_complete_observed_v2(
                self.bundle, self.client_grant, intent=intent, expected_anchor=anchor, admission=admission, report=report)
            if completed.state == "observed" and completed.intent == intent and actual_permit == permit:
                return terminal
        except Exception:
            return None
        return None

    async def close_v1(self):
        if self.owner_loop is not None and self.owner_loop is not asyncio.get_running_loop():
            raise RuntimeError("D07 close must run on its owning host loop")
        self._closed = True
        self._pending.clear()
        self._queued_ids.clear()
        if self._runner_task is not None:
            # Waiting does not cancel the one provider task. The installed
            # adapter/Authority own its original claim if shutdown interrupts.
            await asyncio.shield(self._runner_task)
        self._pre_read_results.clear()
        self._adapters.clear()

    def read_current_command_identity_v1(self, db, *, namespace, operation_kind, request,
            operation_id=None, requested_activity_id=None):
        from .domain_production_read_plans_v1 import CurrentDomainCommandIdentityV1
        if db is not self._db or not db.in_transaction or not operation_id or not requested_activity_id:
            raise ValueError("D07 intended execution identity requires its actual current command")
        effect = "d07-effect:" + canonical_digest((namespace, operation_id, requested_activity_id, operation_kind, request))[:48]
        return CurrentDomainCommandIdentityV1(requested_activity_id, effect, "context", "internal")

    def pre_read_cost_fact_v1(self, job_id):
        fact = self._pre_read_cost_facts.get(job_id)
        if fact is None:
            raise ValueError("D07 exact independent cost fact has not been read outside GraphWorker")
        return fact

    def pre_read_result_v1(self, job_id):
        result = self._pre_read_results.get(job_id)
        if result is None:
            raise ValueError("D07 exact scoped result has not been read outside GraphWorker")
        return result

    def pre_read_accounting_grant_v1(self, job_id):
        value = self._accounting_grants.get(job_id)
        if value is None:
            raise ValueError("D07 original accounting permit has not been authenticated outside GraphWorker")
        return value

    async def _account_original_cost_v1(self, job_id):
        from .d07_accounting_v1 import (read_current_d07_accounting_request_v1,
            prepare_current_d07_accounting_request_v1, close_current_d07_accounting_request_v1)
        prior = await self.worker.call(lambda graph: read_current_d07_accounting_request_v1(
            graph, self.bootstrap, self.bundle, job_id=job_id))
        if prior is not None:
            request, state, result = prior
            if state == "committed":
                await self.authority_client.accounting_recover_finish_v1(self.bundle, self.client_grant,
                    accounting_request=request)
                return result
            if state == "open":
                try:
                    await self.authority_client.accounting_recover_finish_v1(self.bundle, self.client_grant,
                        accounting_request=request)
                except Exception:
                    grant = await self.authority_client.accounting_begin_v1(self.bundle, self.client_grant,
                        accounting_request=request)
                    await self.authority_client.accounting_finish_v1(self.bundle, self.client_grant,
                        accounting_request=request, accounting_grant=grant)
                self._closed_accounting_requests[job_id] = request
                await self.worker.call(lambda graph: close_current_d07_accounting_request_v1(
                    graph, self.bootstrap, self.bundle, job_id=job_id, request=request))
        port = self.graph._GraphCoordinator__content_fence_v2
        policy = self.bundle.installation_policy
        # This bridge waits on the owning host loop from a helper thread,
        # never from the GraphWorker or while a Graph transaction is held.
        anchor = await asyncio.to_thread(port.current_anchor, namespace=policy.namespace,
            authority_namespace=policy.authority_namespace)
        request = await self.worker.call(lambda graph: prepare_current_d07_accounting_request_v1(
            graph, self.bootstrap, self.bundle, job_id=job_id, anchor=anchor))
        grant = await self.authority_client.accounting_begin_v1(self.bundle, self.client_grant, accounting_request=request)
        await self.authority_client.accounting_validate_v1(self.bundle, self.client_grant,
            accounting_request=request, accounting_grant=grant)
        self._accounting_grants[job_id] = (request, grant)
        try:
            result = await self.worker.call(lambda graph: graph.reconcile_current_d07_cost_v1(
                self.bootstrap, self.bundle, job_id=job_id))
        except BaseException:
            # A SQL rollback does not authorize another provider admission.
            # The original accounting attempt remains recoverable by its ID.
            raise
        await self.authority_client.accounting_finish_v1(self.bundle, self.client_grant,
            accounting_request=request, accounting_grant=grant)
        return result

    def _configured(self):
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        workflows = self.bundle.model_workflows
        if workflows is None or workflows.d07_cognition is None:
            raise MissingProductionOriginalV1("explicit_installed_d07_cognition_workflow")
        return workflows.d07_cognition

    def _current_body_policy(self, db, namespace):
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='d02_fixed_body_policies_v1'").fetchone() is None:
            raise MissingProductionOriginalV1("explicit_owner_d07_fixed_body_policy")
        rows = db.execute("SELECT policy_id,version FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? "
            "AND status='active' AND json_extract(policy_json,'$.work_kind')='d07.cognition' ORDER BY policy_id,version LIMIT 3",
            namespace.as_tuple).fetchall()
        if len(rows) != 1:
            raise MissingProductionOriginalV1("one_explicit_current_d07_fixed_body_policy")
        return rows[0]

    def prepare_current_stage_in_transaction_v1(self, db, frame, stage):
        if db is not self._db or not db.in_transaction:
            raise ValueError("D07 preparation requires its actual bound W01 transaction")
        workflow = self._configured()
        namespace = frame.envelope.authority.namespace
        if stage.work_kind == "concern":
            question = read_current_d07_semantic_question_v1(db, self.d11_issuer, namespace,
                stage.request.trigger_original_ref)
            if question is not None:
                target = resolve_current_d07_semantic_target_v1(db, self.d11_issuer, frame, question)
                stage = replace(stage, provenance={**stage.provenance, "semantic_question": question, "semantic_target": target})
            from .d07_reflection_execution_v1 import read_actual_d07_reflection_request_v1
            reflection = read_actual_d07_reflection_request_v1(db, self.d11_issuer, namespace, stage.request.trigger_original_ref)
            if reflection is not None:
                choice = stage.provenance["choice"]
                ticket = next(t for t in stage.provenance["tickets"] if t.ticket_id == choice.ticket_id)
                if set(ticket.source_refs) != set(reflection.source_refs):
                    raise ValueError("D07 reflection request differs from the actual fair chosen source scope")
                stage = replace(stage, work_kind="reflection", provenance={**stage.provenance,
                    "reflection_request": asdict(reflection)})
        ids = d07_execution_ids_v1(namespace, frame.envelope.identity.operation_id, stage.work_kind)
        original = read_prepared_d07_execution_v1(db, self.d11_issuer, namespace, ids["job"])
        if original is not None:
            job = get_job(db, original.job_id)
            if (job.continuation["request"] != _json(stage.request)
                    or (job.activity_id, job.effect_id, job.operation_id) !=
                       (frame.envelope.identity.activity_id, frame.envelope.identity.effect_id, frame.envelope.identity.operation_id)):
                raise ValueError("D07 prepared operation reused for a different request")
            require_current_d07_content_reads_v1(db, original, issuer=self.d11_issuer)
            envelope = replace(frame.envelope, version_guard=replace(frame.envelope.version_guard,
                resource_lease_versions=(VersionedRef(original.quote_id, original.quote_version),)))
            return D07PreparationStageV1(replace(frame, envelope=envelope),
                replace(stage, envelope=envelope, proposal=replace(stage.proposal, envelope=envelope),
                    input_digest=original.stage_input_digest), original, job, (), frame.snapshot.versions, True)
        from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        reader = getattr(self.graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
        if reader is None:
            raise MissingProductionOriginalV1("explicit_owner_role_clock_installation")
        mapping = read_current_role_clock_installation_v1(reader, db, namespace)
        policy_id, policy_version = self._current_body_policy(db, namespace)
        return prepare_d07_execution_in_transaction_v1(db, frame=frame, stage=stage, workflow=workflow,
            installation_id=self.bundle.installation_policy.installation_id, d11_issuer=self.d11_issuer,
            resource_issuer=self.resource_issuer, body_authority=self.body_authority, clock_mapping=mapping,
            body_policy_id=policy_id, body_policy_version=policy_version)

    def verify_preparation_in_transaction_v1(self, db, preparation):
        if db is not self._db:
            raise ValueError("D07 preparation verification crossed installation database")
        verify_current_d07_preparation_stage_v1(db, preparation, self)

    def make_persistent_job_v1(self, stage, original_ref):
        original = read_prepared_d07_execution_v1(self._db, self.d11_issuer, stage.envelope.authority.namespace,
            d07_execution_ids_v1(stage.envelope.authority.namespace, stage.envelope.identity.operation_id, stage.work_kind)["job"])
        if original is None or original.stage_input_digest != stage.input_digest:
            raise ValueError("D07 queue has no actual prepared immutable original")
        return get_job(self._db, original.job_id)

    def read_current_original_ref_v1(self, db, namespace, ref):
        return read_current_original_ref_v1(db, namespace, ref, issuer=self.d11_issuer)

    def read_registered_simulation_request(self, ref):
        return read_registered_simulation_request_v1(self._db, self.d11_issuer,
            self.bundle.installation_policy.namespace, ref)

    def read_verified_terminal(self, ref):
        # The model body was independently released over mTLS and durably
        # adopted by the fixed worker completion transaction. No RPC occurs
        # here, particularly when called while W01 holds a Graph transaction.
        row = read_d07_original_v1(self._db, self.d11_issuer, self.bundle.installation_policy.namespace,
            "execution", ref)
        if row is None:
            raise ValueError("D07 actual durable verified terminal missing")
        return decode_d07_execution_original_v1(row[0])

    def verify_prepared_terminal(self, execution, frame):
        if type(execution) is not D07ExecutionOriginalV1 or not self._db.in_transaction:
            raise ValueError("D07 current terminal proof requires its actual W01 transaction")
        original = read_prepared_d07_execution_v1(self._db, self.d11_issuer, frame.envelope.authority.namespace,
            d07_execution_ids_v1(frame.envelope.authority.namespace, execution.operation_id, execution.work_kind)["job"])
        if (original is None or execution != self.read_verified_terminal(execution.terminal_ref)
                or execution.input_digest != original.stage_input_digest
                or execution.activation_generation != frame.activation_generation
                or json.loads(original.owner_guard_json) != asdict(frame.owner_guard)):
            raise ValueError("D07 current Owner/generation/actual terminal differs from original")
        require_current_d07_content_reads_v1(self._db, original, issuer=self.d11_issuer)
        paid = read_d07_original_v1(self._db, self.d11_issuer, original.namespace, "paid_cost", original.job_id)
        body = read_d07_original_v1(self._db, self.d11_issuer, original.namespace, "body_cost", original.job_id)
        if (paid is None or body is None or not paid[0]["paid"] or body[0]["unpaid_cost"]
                or execution.cost_receipt_refs != (paid[0]["cost_ref"],)):
            raise ValueError("D07 actual paid cost/body original missing")

    async def execute_current_d07_job_v1(self, job):
        """One invocation consumes at most the original Authority start right."""
        from ..host.v2_installation import V2InstallationAssembly
        from ..host.authority_client import AuthorityClient
        from ..host.authority_profile import AdminModelWorkflowV2
        from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
        from ..model_broker.broker import ModelProviderDescriptor
        from ..host.astrbot_model_call import AstrBotModelProvider
        from ..host.model_egress_executor import HostModelEgressExecutor
        workflow = self._configured()
        if (type(self.installation) is not V2InstallationAssembly or self.worker is None
                or type(self.authority_client) is not AuthorityClient or type(self.client_grant) is not InstallationGrantV2
                or self.context is None or type(workflow) is not AdminModelWorkflowV2):
            return {"status": "hold", "missing_inputs": ("actual_installed_d07_host_execution_binding",), "job_id": job.job_id}
        if self.owner_loop is not asyncio.get_running_loop():
            raise RuntimeError("D07 actual model executor must run on the owning AstrBot loop")
        graph_args = {"job_id": job.job_id}
        bundle = self.bundle
        from .d07_graph_stages_v1 import read_resume_current_d07_metadata_v1
        resume_job, accounting, existing_intent = await self.worker.call(lambda graph:
            read_resume_current_d07_metadata_v1(graph, self.bootstrap, bundle, **graph_args))
        if resume_job.phase == "completed":
            return await self.worker.call(lambda graph: graph.resume_current_d07_behavior_v1(self.bootstrap, bundle, **graph_args))
        if existing_intent is not None:
            from .model_cost_settlement import read_original_model_cost
            try:
                observed = await self.authority_client.model_terminal_fact_v2(bundle, self.client_grant, intent=existing_intent)
                if observed[0].state == "dispatch_started" and observed[3] is None:
                    original_permit = observed[1]
                    recovered = None if original_permit is None else await self._recover_local_observation_v1(
                        existing_intent, original_permit.pinned_anchor, job.job_id)
                    if recovered is None:
                        return {"status": "original_terminal_unknown", "job_id": job.job_id}
                    observed = await self.authority_client.model_terminal_fact_v2(bundle, self.client_grant, intent=existing_intent)
            except Exception:
                # An unavailable original query cannot grant a new start or a
                # new content-fence begin after an uncertain consumed claim.
                return {"status": "original_terminal_unknown", "job_id": job.job_id}
            if observed[0].state == "observed" and observed[3] is not None:
                self._adapters.pop(job.job_id, None)
                self._pre_read_cost_facts[job.job_id] = read_original_model_cost(lambda _intent: observed, existing_intent)
                # A known charge stays known even when its actual accounting
                # permit or SQL reconciliation needs later recovery.
                await self._account_original_cost_v1(job.job_id)
            elif observed[0].state != "prepared":
                return {"status": "original_terminal_unknown", "job_id": job.job_id}
        await self.worker.call(lambda graph: graph.acquire_current_d07_execution_v1(self.bootstrap, bundle, **graph_args))
        read = await self.worker.call(lambda graph: graph.read_acquired_current_d07_execution_v1(self.bootstrap, bundle, **graph_args))
        if isinstance(read, dict):
            return read
        prepared, current_job, call, draft, anchor, sealed_intent, trusted_umo = read
        if sealed_intent is None:
            record, permit = await self.authority_client.model_prepare_fenced_v1(bundle, self.client_grant,
                draft=draft, expected_anchor=anchor)
        else:
            record, permit = await self.authority_client.model_recover_fenced_v1(bundle, self.client_grant, intent=sealed_intent)
            if record.intent != sealed_intent:
                raise ValueError("D07 recovered call differs from original consumed claim")
            draft, anchor = ModelEgressDraftV1.from_intent(sealed_intent), permit.pinned_anchor
        if ModelEgressDraftV1.from_intent(record.intent) != draft or permit.pinned_anchor != anchor:
            raise ValueError("D07 Authority prepared another original call")
        if record.state == "prepared":
            await self.worker.call(lambda graph: graph.seal_current_d07_egress_v1(self.bootstrap, bundle,
                intent=record.intent, permit=permit, **graph_args))
            descriptor = ModelProviderDescriptor(workflow.provider_id, "astrbot-openai-official-v1", workflow.model_id,
                frozenset({"text"}), frozenset({workflow.purpose}), frozenset({workflow.privacy_tier}),
                workflow.provider_config_ref, "unknown", False, False)
            adapter = AstrBotModelProvider(context=self.context, host_loop=self.owner_loop, trusted_umo=trusted_umo,
                descriptor=descriptor, admin_model=workflow, installation_bundle=bundle)
            self._adapters[current_job.job_id] = adapter
            executor = HostModelEgressExecutor(authority=self.authority_client, bundle=bundle, grant=self.client_grant, adapter=adapter)
            terminal = await executor.execute_once(intent=record.intent, expected_anchor=anchor,
                request=call, d07_original=prepared)
            if terminal is None:
                terminal = await self._recover_local_observation_v1(record.intent, anchor, current_job.job_id)
                if terminal is None:
                    return {"status": "original_terminal_unknown", "job_id": current_job.job_id}
        elif record.state != "observed":
            # dispatch_started/unknown are inspection-only. A renewed worker
            # lease can never manufacture another Authority admission.
            terminal = await self._recover_local_observation_v1(record.intent, anchor, current_job.job_id)
            if terminal is None:
                return {"status": "original_terminal_unknown", "job_id": current_job.job_id}
        from .model_cost_settlement import read_original_model_cost
        facts = await self.authority_client.model_terminal_fact_v2(bundle, self.client_grant, intent=record.intent)
        if facts[0].state == "observed" and facts[3] is not None:
            self._adapters.pop(current_job.job_id, None)
        self._pre_read_cost_facts[current_job.job_id] = read_original_model_cost(lambda _intent: facts, record.intent)
        paid = await self._account_original_cost_v1(current_job.job_id)
        if paid.get("paid") is not True:
            return paid
        request = await self.worker.call(lambda graph: graph.prepare_current_d07_result_read_v1(self.bootstrap, bundle, **graph_args))
        try:
            result = await self.authority_client.d07_cognition_result_read_v1(bundle, self.client_grant, read_request=request)
        except BaseException:
            try:
                await self.authority_client.d07_cognition_result_recover_finish_v1(bundle, self.client_grant, read_request=request)
            except Exception:
                pass
            raise
        result.require_original(record.intent, prepared)
        self._pre_read_results[current_job.job_id] = result
        try:
            finished = await self.worker.call(lambda graph: graph.finish_current_d07_execution_v1(self.bootstrap, bundle, **graph_args))
        finally:
            # The authenticated result is needed only for this fixed SQL
            # import. Later adoption reads the durable signed original; a
            # failed import must recheck the original scoped Authority read.
            self._pre_read_results.pop(current_job.job_id, None)
        if finished.get("status") != "actual_execution_completed":
            return finished
        return await self.worker.call(lambda graph: graph.resume_current_d07_behavior_v1(self.bootstrap, bundle, **graph_args))
