"""Explicit package-status authentication routing; no maintenance receipt is faked."""
import json
from uuid import uuid4
import pytest
from sylanne3.workbench_api.http_transport import WorkbenchHttpTransport,TransportConfig
from sylanne3.workbench_api.service import AuthenticatedSession,WorkbenchService
from rewrite.tests.alpha1.d12.test_workbench_http_transport import Request,Csrf,SCOPE


@pytest.mark.asyncio
async def test_package_status_selects_only_exact_status_auth_and_never_content_failure_fallback(tmp_path):
    original=str(uuid4());calls=[]
    class Sessions:
        def resolve(self,**arguments):
            calls.append(('content',arguments));return None
        def resolve_package_status(self,**arguments):
            calls.append(('package',arguments))
            if arguments['operation_id']!=original:return None
            return AuthenticatedSession('owner:independent-account','server-session',
                {SCOPE:frozenset({'workbench.package_status'})},{SCOPE:frozenset({'owner'})},
                {SCOPE:frozenset({'audit'})},host_username='dashboard-user',package_operation_id=original)
    subject=WorkbenchHttpTransport(WorkbenchService(),Sessions(),Csrf(),TransportConfig('https://dashboard.local',tmp_path))
    body={'schema_version':'d12.contract.v1','action':'read_package_operation','scope':SCOPE,'purpose':'audit','audience':'owner',
        'operation_id':str(uuid4()),'input':{'operation_id':original}}
    result=await subject.command(Request(json.dumps(body).encode()))
    assert result['problem']['code']=='provider_unavailable'
    assert [c[0] for c in calls]==['package'] and calls[0][1]['operation_id']==original
    body.update(action='read_character_view',purpose='workbench_view',input={'view_type':'overview'})
    result=await subject.command(Request(json.dumps(body).encode()))
    assert result['problem']['code']=='owner_session_locked'
    assert [c[0] for c in calls]==['package','content']


@pytest.mark.asyncio
async def test_malformed_package_selector_and_browser_authority_fields_never_reach_resolver(tmp_path):
    class Sessions:
        def resolve(self,**arguments):raise AssertionError('malformed explicit status cannot use ordinary auth')
        def resolve_package_status(self,**arguments):raise AssertionError('malformed status cannot query Authority')
    subject=WorkbenchHttpTransport(WorkbenchService(),Sessions(),Csrf(),TransportConfig('https://dashboard.local',tmp_path))
    body={'schema_version':'d12.contract.v1','action':'read_package_operation','scope':SCOPE,'purpose':'audit','audience':'owner',
        'operation_id':str(uuid4()),'input':{'operation_id':str(uuid4()),'current_owner':True}}
    assert (await subject.command(Request(json.dumps(body).encode())))['problem']['code']=='invalid_request'
    body['input']={'operation_id':'../other-installation'}
    assert (await subject.command(Request(json.dumps(body).encode())))['problem']['code']=='invalid_request'
    body.update(action='accept_package_switch',purpose='workbench_user_action',input={
        'candidate_cohort_ref':'registered:release','expected_selection_digest':'a'*64,'expected_lifecycle_epoch':3,'package_path':'/tmp/browser'})
    with pytest.raises(ValueError,match='input fields'):
        WorkbenchService._parse(body)
