"""Real installed Owner/external Source plan; controlled provider transport only.

The donor uses localhost mTLS Authority and MockTransport/OneBot AsyncMock.
This first node authenticates the new Plan B transaction and its durable
original. Generation/review/final dispatch require their own later assertion.
"""
import asyncio
from dataclasses import replace
import json
import time
import traceback

import pytest

from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
)
from test_current_domain_production_v1 import command
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.model_broker.contact_expression_v1 import GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION
from sylanne3.domains.d10 import ContactPolicy, ProactiveOpportunity, contact_policy_key, opportunity_key
from sylanne3.domains.d08.contact_plan_v1 import contact_ids_v1
from sylanne3.domains.d08.contact_plan_v2 import PLAN,PROVENANCE,ELIGIBILITY
from sylanne3.runtime.domain_production_inputs_v1 import SetCurrentContactPolicyInputRequestV1, CreateCurrentContactOpportunityInputRequestV1
from sylanne3.runtime.contact_plan_adoption_v2 import AdoptCurrentContactExpressionPlanRequestV2, read_adopted_contact_plan_v2


def contact_workflows(base, shared):
    return replace(base,
        contact_generation=AdminModelWorkflowV2(work_kind='contact_generation',purpose='proposal',
            template_version=GENERATION_TEMPLATE_VERSION,max_output_tokens=128,quote_ceiling={'output_tokens':128},**shared),
        contact_review=AdminModelWorkflowV2(work_kind='contact_review',purpose='proposal',
            template_version=REVIEW_TEMPLATE_VERSION,max_output_tokens=128,quote_ceiling={'output_tokens':128},**shared))


async def run_external_contact_plan_case(tmp_path, installed_d04_root, *, workflow_builder=contact_workflows, before_plan=None, after_plan=None, after_plan_async=None, private_reply_dispatch_policy=None):
    initialized={}
    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            adopt_mapping_and_clock(case)
            initialized.update(case)
        await asyncio.to_thread(initialize)

    async def after_c02(current):
        case={**initialized,**current}
        adopted={}
        # The donor resumes its actual TLS channel after root initialization.
        # Rebind the installed synchronous port to that fresh channel grant;
        # retain the same real Authority services, journals and package.
        from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
        await asyncio.to_thread(install_actual_root_authority_case_v3,case,owner_loop=asyncio.get_running_loop())
        from contact_authority_acceptance_support_v2 import install_actual_contact_authority_case_v2
        await asyncio.to_thread(install_actual_contact_authority_case_v2,case)
        def adopt():
            graph,store,ns=case['graph'],case['store'],case['namespace']
            for domain in ('d08','d10','d11'):
                if domain not in graph._GraphCoordinator__providers:
                    registration=case['domain_registry'].registrations[domain]
                    graph.register_provider(case['bootstrap'],domain,registration.provider,
                        registration.proposal_schema,registration.proposal_schema_hash)
            with store._lock:
                route_ref,wire=store._db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.account_binding' AND valid=1 ORDER BY token",ns.as_tuple).fetchone()
            route=json.loads(wire);audience=case['ingress'].conversation_ref;now=time.time()
            if before_plan is not None:
                before_plan(case, route, audience, now)
            policy=ContactPolicy('contact-policy:installed-v2',ns,1,route['entity_id'],'private','conversation',True,False,1,now-60,now+3600)
            opportunity=ProactiveOpportunity('contact-opportunity:installed-v2',ns,case['source_ref'],route['entity_id'],'private','conversation',now-60,now+3600)
            command(case,'set_contact_policy',SetCurrentContactPolicyInputRequestV1(policy),producer=True)
            command(case,'create_contact_opportunity',CreateCurrentContactOpportunityInputRequestV1(opportunity),audience=audience,producer=True)
            ids=contact_ids_v1(ns,case['source_ref'],route['entity_id'],'private_text')
            try:
                result=command(case,'adopt_contact_expression_plan_v2',
                    AdoptCurrentContactExpressionPlanRequestV2(opportunity_key(ns,opportunity.opportunity_id).token,
                        contact_policy_key(ns,policy.policy_id).token,route_ref),audience=audience,activity_id=ids['activity'])
            except AssertionError:
                # Preserve the original product stack, never locals/request
                # bodies or credentials. The common refusal result is terse.
                refusal=case['graph']._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
                traceback.print_exception(type(refusal),refusal,refusal.__traceback__)
                raise
            assert result['coverage']=='complete' and len(result['receipt']['write_versions'])==3
            assert {json.loads(row[0])[4] for row in result['receipt']['write_versions']}=={PLAN,PROVENANCE,ELIGIBILITY}
            with store._lock:
                store._db.execute('BEGIN')
                try:
                    plan,expression,raw,digest=read_adopted_contact_plan_v2(store._db,namespace=ns,contact_id=ids['contact'],issuer=case['d11_issuer'])
                    from sylanne3.domains.d08.contact_plan_v2 import contact_plan_keys_v2
                    assert plan.schema==PLAN and expression.plan_ref.ref==contact_plan_keys_v2(plan)[0].token
                    assert raw['producing_operation_id']==result['operation_id'] and digest
                finally:store._db.rollback()
            if after_plan is not None:
                after_plan(case, plan, expression, ids)
            adopted.update(plan=plan,expression=expression,ids=ids)
        await asyncio.to_thread(adopt)
        if after_plan_async is not None:
            await after_plan_async(case,adopted['plan'],adopted['expression'],adopted['ids'])
    await real_owner_case(tmp_path,'owned',natural_workflow_builder=workflow_builder,
        installed_package_root=installed_d04_root,after_role_initialization=after_role,
        continue_to_ingress=True,after_c02=after_c02,enable_d09_workbench=True,enable_d04_root_cpu=True,
        enable_d10_offline_ticks=True,enable_c04_body_work=True,
        extra_owner_purposes=('context','consolidation','expression'),
        private_reply_dispatch_policy=private_reply_dispatch_policy)


@pytest.mark.asyncio
async def test_installed_owner_external_contact_plan_durable_three_members(tmp_path, installed_d04_root):
    await run_external_contact_plan_case(tmp_path, installed_d04_root)
