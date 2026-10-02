"""Actual installed Plan V2 -> finite quote/reservation/queued job V2.

The shared donor issues real Owner/Core/TLS/current Source originals. Provider
HTTP uses its MockTransport. This node has no generation/review/final claim.
"""
from dataclasses import fields
import traceback

import pytest

from test_installed_contact_external_v2 import (
    installed_d04_root, run_external_contact_plan_case,
)
from test_current_domain_production_v1 import command
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
from sylanne3.model_broker.contact_expression_v2 import (
    GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION,
)
from sylanne3.runtime.contact_model_job_v2 import contact_model_ids_v2, read_contact_prepared_v2
from sylanne3.runtime.contact_product_adapter_v2 import PrepareCurrentContactModelRequestV2
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime_contracts import canonical_digest


def paid_workflows(base, shared):
    common = {f.name: getattr(base, f.name) for f in fields(base)
              if f.name not in {'version', 'contact_generation', 'contact_review'}}
    return AdminModelWorkflowsV3(3, **common,
        contact_generation=AdminModelWorkflowV2(work_kind='contact_generation', purpose='proposal',
            template_version=GENERATION_TEMPLATE_VERSION, max_output_tokens=128,
            quote_ceiling={'output_tokens': 128}, **shared),
        contact_review=AdminModelWorkflowV2(work_kind='contact_review', purpose='proposal',
            template_version=REVIEW_TEMPLATE_VERSION, max_output_tokens=128,
            quote_ceiling={'output_tokens': 128}, **shared))


@pytest.mark.asyncio
async def test_installed_external_contact_v2_quoted_once_preparation(tmp_path, installed_d04_root):
    def after_plan(case, plan, expression, cause):
        graph, store, ns = case['graph'], case['store'], case['namespace']
        ids = contact_model_ids_v2(plan, 'contact_generation')
        request = PrepareCurrentContactModelRequestV2(plan.contact_id, 'contact_generation')
        def prepare():
            try:
                return command(case, 'prepare_contact_model_v2', request,
                    operation_id=ids['prepare'], activity_id=plan.activity_id, audience=plan.audience_id)
            except AssertionError:
                error = graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                traceback.print_exception(type(error), error, error.__traceback__)
                raise
        result = prepare()
        assert result['coverage'] == 'deferred' and result['job_states'] == [[ids['job'], 'queued']]
        assert len(result['receipt']['write_versions']) == 1
        with store._lock:
            store._db.execute('BEGIN')
            try:
                prepared, frozen = read_contact_prepared_v2(store._db, namespace=ns,
                    job_id=ids['job'], issuer=case['d11_issuer'])
                quote = case['d02_issuer'].original_signed_quote(store._db, prepared.quote_id, prepared.quote_version)
                job = get_job(store._db, prepared.job_id)
                lease = get_budget_lease(store._db, plan.parent_budget_lease_id)
                reserved = dict(lease.reserved)
                assert prepared.schema == 'd10.contact-model-prepared.v2'
                assert frozen.input.adopted_plan == plan and frozen.input.expression_plan == expression
                assert job.phase == 'queued' and job.operation_id == plan.generation_reservation_id
                assert quote.operation_id == prepared.prepare_operation_id and canonical_digest(quote) == prepared.quote_digest
                assert reserved.get('output_tokens', 0) >= 128
            finally:
                store._db.rollback()
        repeated = prepare()
        assert repeated == result
        assert dict(get_budget_lease(store._db, plan.parent_budget_lease_id).reserved) == reserved
    await run_external_contact_plan_case(tmp_path, installed_d04_root,
        workflow_builder=paid_workflows, after_plan=after_plan)
