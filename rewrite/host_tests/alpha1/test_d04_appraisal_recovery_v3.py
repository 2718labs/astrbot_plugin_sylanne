"""Actual installed D04 channel distinguishes read refusal from paid recovery.

Graph and network are explicit dispatch doubles; these tests grant no Source or
installation qualification and never construct a provider adapter.
"""
from types import SimpleNamespace
import pytest
from sylanne3.host.installed_d04_appraisal_driver_v3 import _run_appraisal_with_retained_inputs_v3
from sylanne3.runtime.d04_appraisal_driver_v3 import D04SettledAppraisalLocatorV3


@pytest.mark.asyncio
@pytest.mark.parametrize("completed", [False, True])
async def test_actual_channel_only_recovers_a_typed_completed_original(completed):
    class FirstReadRefusal(ValueError):
        pass

    failure = FirstReadRefusal("actual Source read refused")
    calls = []

    class Graph:
        def prepare_post_c02_appraisal_v3(self, *args, **kwargs):
            calls.append("prepare")
            return {"status": "queued"}
        def acquire_post_c02_appraisal_v3(self, *args, **kwargs):
            calls.append("acquire")
            return {"status": "running"}
        def read_acquired_appraisal_v3(self, *args, **kwargs):
            calls.append("read")
            if not completed:
                raise failure
            return D04SettledAppraisalLocatorV3("job", "a" * 64, "result")
        def adopt_post_c02_appraisal_v3(self, *args, **kwargs):
            calls.append("adopt")
            return {"status": "adopted", "job_id": "job"}

    async def graph_call(callback, *, slot):
        return callback(Graph())

    runtime = SimpleNamespace(_v2_bootstrap=object())
    async def run():
        return await _run_appraisal_with_retained_inputs_v3(runtime, None, None, None, None,
            graph_call=graph_call, context=None, trusted_umo=None,
            c02_operation_id="c02", source_ref="source")
    if completed:
        assert await run() == {"status": "adopted", "job_id": "job"}
        assert calls == ["prepare", "acquire", "read", "adopt"]
    else:
        with pytest.raises(FirstReadRefusal) as rejected:
            await run()
        assert rejected.value is failure
        assert calls == ["prepare", "acquire", "read"]
