"""The installed host wrapper uses the original ingress identity for D13."""

import pytest

from sylanne3.graph_coordinator import D13InboundTurnReceiptV1
from sylanne3.graph_types import AtomKey
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.first_ingress_v2 import ingress_ids

from test_reply_entity_route_v2 import CANONICAL_CONVERSATION, _current_join
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401
from test_d13_confirmed_inbound_turn_v1 import _writer


class _Worker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, function, *args):
        return function(self.graph, *args)


@pytest.mark.asyncio
async def test_host_wrapper_commits_once_and_rejects_unrelated_ingress(
        canonical_private_case):
    store, graph, bootstrap, namespace, policy, *_ = canonical_private_case
    c02, source_token = _current_join(canonical_private_case)
    source_id = AtomKey.from_token(source_token).owner.subject
    original = store._db.execute(
        "SELECT operation_id FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_id,),
    ).fetchone()[0]
    assert ingress_ids(source_id)[2] == original
    _writer(canonical_private_case)
    port = graph._GraphCoordinator__content_fence_v2
    runtime = object.__new__(RuntimeContext)
    runtime._v2_policy = policy
    runtime._v2_installation_grant = port.installation_grant
    runtime._v2_port = port
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = bootstrap
    runtime._v2_namespace_provisioned = True
    runtime._v2_namespace = namespace
    envelope = HostIngressEnvelope(
        namespace, "platform", CANONICAL_CONVERSATION, "sender", "message",
        "hello", None, 1.0, "private",
        SourceLineage(source_id, "reported", "host", "external_report",
                      "reported_claim"))

    first = await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id=original, c02_operation_id=c02.operation_id,
        envelope=envelope)
    assert type(first) is D13InboundTurnReceiptV1
    assert await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id=original, c02_operation_id=c02.operation_id,
        envelope=envelope) == first
    assert await runtime.commit_confirmed_d13_inbound_turn_v1(
        ingress_operation_id="unrelated", c02_operation_id=c02.operation_id,
        envelope=envelope) is None
    runtime._v2_model_bundle = None
    assert await runtime.schedule_d13_deterministic_precompression_v2(
        ingress_operation_id=original, envelope=envelope) is None
    rows = store._db.execute(
        "SELECT type_name FROM graph_atoms WHERE bot=? AND persona=? AND "
        "type_name IN ('d09.turn_order.v1','d09.turn_slot.v1',"
        "'d09.turn_completion.v1')", namespace.as_tuple).fetchall()
    assert len(rows) == 3


@pytest.mark.parametrize('paid_state',['exception','pending_confirmation','absent'])
@pytest.mark.asyncio
async def test_actual_main_d13_drain_does_not_fallback_after_unknown_paid_attempt(paid_state):
    """Execute the actual Main method body; host/provider services are controlled."""
    import ast
    import asyncio
    from pathlib import Path
    from types import SimpleNamespace
    source=Path(__file__).resolve().parents[4]/'main.py'
    tree=ast.parse(source.read_text(encoding='utf-8'))
    methods=[node for node in ast.walk(tree)if isinstance(node,ast.AsyncFunctionDef)
             and node.name=='_drain_d13_precompression_v2']
    assert len(methods)==1
    calls=[];logs=[]
    async def paid(*args,**kwargs):
        calls.append('paid')
        if paid_state=='exception':raise RuntimeError('original paid outcome unknown')
        if paid_state=='pending_confirmation':return SimpleNamespace(status='pending_confirmation')
        return None
    async def deterministic(**kwargs):
        calls.append('deterministic');host._encoding_stopping=True
        return None,SimpleNamespace(job_id='original:deterministic')
    runtime=SimpleNamespace(schedule_d13_deterministic_precompression_v2=deterministic)
    installation=object();envelope=SimpleNamespace(conversation_ref='conversation:one')
    host=SimpleNamespace(_runtime=runtime,_v2_installation=installation,context=object(),
        _d13_pending_jobs={},_d13_pending_expiries={},_d13_pending_schedules={'operation:one':(envelope,'umo:one')},
        _d13_scan_needed=False,_encoding_stopping=False,_d13_drain_task=None)
    namespace={'asyncio':asyncio,'run_installed_d13_paid_precompression_v1':paid,
        'logger':SimpleNamespace(warning=lambda *args:logs.append(args),exception=lambda *args:logs.append(args))}
    module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),methods[0]],type_ignores=[])
    exec(compile(ast.fix_missing_locations(module),str(source),'exec'),namespace)
    await namespace['_drain_d13_precompression_v2'](host,runtime,installation)
    assert calls==(['paid','deterministic']if paid_state=='absent'else['paid'])
    assert bool(host._d13_pending_jobs)==(paid_state=='absent')
    assert not host._d13_pending_schedules
