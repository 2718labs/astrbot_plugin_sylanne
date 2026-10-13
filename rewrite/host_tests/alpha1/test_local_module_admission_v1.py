"""Native startup intent, actual first egress and original recovery boundaries."""
from dataclasses import FrozenInstanceError
from types import MethodType, SimpleNamespace

import pytest
from tests.alpha1.d12.test_owner_graph_lease import owner_graph

from sylanne3.runtime.local_module_admission_v1 import (
    LocalModuleAdmissionV1, LocalModuleAdmissionDeniedV1, MODULE_IDS_V1,
    OPERATION_MODULES_V1, MODEL_MODULES_V1, required_operation_modules_v1,
)


def disabled(*modules):
    values = dict.fromkeys(MODULE_IDS_V1, True)
    values.update(dict.fromkeys(modules, False))
    return LocalModuleAdmissionV1.from_config_v1(values)


def test_exact_native_snapshot_and_closed_production_catalog():
    from sylanne3.runtime.domain_production_registry_v1 import _OPERATIONS
    from sylanne3.runtime.domain_production_inputs_v1 import _PRODUCERS

    raw = dict.fromkeys(MODULE_IDS_V1, True)
    frozen = LocalModuleAdmissionV1.from_config_v1(raw)
    raw["d13"] = False
    assert frozen.flags == dict.fromkeys(MODULE_IDS_V1, True)
    assert LocalModuleAdmissionV1.from_config_v1(None) == frozen
    with pytest.raises(FrozenInstanceError):
        frozen.enabled = (False,) * 13
    for invalid in ({}, {**raw, "future": True}, {**raw, "d13": 1}, {**raw, "d13": None}):
        with pytest.raises(ValueError):
            LocalModuleAdmissionV1.from_config_v1(invalid)
    assert set(OPERATION_MODULES_V1) == set(_OPERATIONS) | {"input:" + name for name in _PRODUCERS}
    with pytest.raises(ValueError):
        required_operation_modules_v1("future_registered_operation")


def test_unrelated_modules_do_not_disable_independent_work_or_original_maintenance():
    for module in MODULE_IDS_V1:
        policy = disabled(module)
        for operation, required in OPERATION_MODULES_V1.items():
            if module in required:
                with pytest.raises(LocalModuleAdmissionDeniedV1) as held:
                    policy.require_v1(required, operation)
                assert held.value.disabled_modules == (module,)
                assert held.value.operation_kind == operation
                assert held.value.reason_code == "local_module_disabled"
            else:
                policy.require_v1(required, operation)
    stopped = disabled(*MODULE_IDS_V1)
    for operation in ("settle_observed_action", "record_host_lifecycle"):
        stopped.require_v1(required_operation_modules_v1(operation), operation)
    disabled("d13").require_v1(required_operation_modules_v1("evaluate_values"), "evaluate_values")


@pytest.mark.asyncio
async def test_actual_model_executor_blocks_first_admission_but_reads_original_terminal():
    from rewrite.host_tests.alpha1 import test_astrbot_model_call as fixture
    from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    from sylanne3.authority_service.v2_model_egress_contract import ModelEgressRecoveryV1, ModelTerminalReceiptV2

    host = fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(host, request)
        calls = []
        async def forbid_admission(self, *args, **kwargs):
            calls.append("admit")
            raise AssertionError("disabled module reached a new paid admission")
        receipt = ModelTerminalReceiptV2(admission.admission_id, intent.call_id,
            intent.request_digest, "a" * 64, "b" * 64, "sha256:" + "c" * 64,
            admission.installation_id, admission.host_incarnation)
        async def terminal(self, *args, **kwargs):
            calls.append("original_terminal")
            return ModelEgressRecoveryV1(intent, "observed", "b" * 64), permit, admission, receipt
        authority.model_admit_dispatch_once_v2 = MethodType(forbid_admission, authority)
        authority.model_terminal_fact_v2 = MethodType(terminal, authority)
        control = HostModelEgressExecutor(authority=authority, bundle=host.bundle,
            grant=grant, adapter=host.adapter)
        assert await control.execute_once(intent=intent, expected_anchor=anchor, request=request) is None
        assert calls == ["admit"] and host.requests == []
        calls.clear()
        executor = HostModelEgressExecutor(authority=authority, bundle=host.bundle,
            grant=grant, adapter=host.adapter, local_module_admission=disabled("d09", "d11"))
        refused = []
        original_gate = executor._require_new_model_attempt_v1
        def observe_gate(self, actual_request):
            try:
                return original_gate(actual_request)
            except LocalModuleAdmissionDeniedV1 as refusal:
                refused.append(refusal)
                raise
        executor._require_new_model_attempt_v1 = MethodType(observe_gate, executor)
        assert await executor.execute_once(intent=intent, expected_anchor=anchor, request=request) is None
        assert calls == [] and host.requests == []
        assert len(refused) == 1 and refused[0].operation_kind == "model:reply"
        assert refused[0].disabled_modules == ("d09", "d11")
        assert await executor.recover_original_terminal(intent) == receipt
        assert calls == ["original_terminal"] and host.requests == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_three_installed_continuations_block_before_any_durable_handoff():
    from sylanne3.host.private_reply_dispatch_driver import InstalledPrivateReplyContinuationV1
    from sylanne3.host.natural_reply_dispatch_driver import InstalledNaturalReplyContinuationV2
    from sylanne3.host.contact_dispatch_driver_v3 import InstalledContactContinuationV3

    # Missing execution ports make any accidental access fail. Admission must
    # run before P0/P2, GraphWorker work or a platform invocation.
    for cls, module in ((InstalledPrivateReplyContinuationV1, "d08"),
                        (InstalledNaturalReplyContinuationV2, "d09"),
                        (InstalledContactContinuationV3, "d10")):
        continuation = object.__new__(cls)
        continuation._local_module_admission = disabled(module)
        with pytest.raises(LocalModuleAdmissionDeniedV1) as held:
            await continuation.dispatch(SimpleNamespace())
        assert held.value.disabled_modules == (module,)


def test_actual_installed_model_slots_require_only_their_production_modules():
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    from sylanne3.host.authority_profile import AdminModelWorkflowV2

    executor = object.__new__(HostModelEgressExecutor)
    models = {slot: object.__new__(AdminModelWorkflowV2) for slot in MODEL_MODULES_V1
              if slot != "d13_precompression"}
    executor._bundle = SimpleNamespace(model_workflows=SimpleNamespace(**models))
    for slot, model in models.items():
        executor._adapter = SimpleNamespace(_admin_model=model)
        request = SimpleNamespace(identity=SimpleNamespace(phase="installed_test"))
        for module in MODULE_IDS_V1:
            executor._local_module_admission = disabled(module)
            if module in MODEL_MODULES_V1[slot]:
                with pytest.raises(LocalModuleAdmissionDeniedV1):
                    executor._require_new_model_attempt_v1(request)
            else:
                executor._require_new_model_attempt_v1(request)
    executor._local_module_admission = disabled("d13")
    with pytest.raises(LocalModuleAdmissionDeniedV1):
        executor._require_new_model_attempt_v1(SimpleNamespace(identity=SimpleNamespace(phase="d13.precompress")))


def test_w01_exact_saved_receipt_survives_disabled_policy_and_new_intent_is_absent(owner_graph):
    from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case
    from tests.alpha1.runtime.test_d12_creator_configuration_v1 import POLICY, _arguments, _read

    store, coordinator, _, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    initial = _read(coordinator, authority, lease)
    request = _arguments(initial, {"d09.expression_policy": {**POLICY, "max_visible_chars": 73}})
    saved = coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    # Seed a historical original with the existing real Owner fixture, then
    # install the disabled startup policy at its trusted composition seam.
    coordinator._GraphCoordinator__local_module_admission = disabled("d12", "d11")
    assert coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request) == saved
    current = _read(coordinator, authority, lease)
    new = _arguments(current, {"d09.expression_policy": {**POLICY, "max_visible_chars": 74}})
    with pytest.raises(LocalModuleAdmissionDeniedV1):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **new)
    assert store._db.execute("SELECT 1 FROM graph_owner_domain_attempts_v3 WHERE operation_id=?",
                             (new["operation_id"],)).fetchone() is None
    assert _read(coordinator, authority, lease)["draft_digest"] == current["draft_digest"]


def test_w01_lost_begin_ack_is_inspected_without_rebegin_or_unproved_commit(owner_graph):
    from tests.alpha1.runtime.test_current_creator_draft_port_v1 import _creator_case
    from tests.alpha1.runtime.test_d12_creator_configuration_v1 import POLICY, _arguments, _read
    from sylanne3.graph_coordinator import UnavailableGuard

    store, coordinator, port, authority, lease = _creator_case(owner_graph,
        fields={"d09.expression_policy": POLICY})
    current = _read(coordinator, authority, lease)
    request = _arguments(current, {"d09.expression_policy": {**POLICY, "max_visible_chars": 73}})
    begin = port.begin_fence
    calls = []
    def lose_begin_ack(**kwargs):
        calls.append("begin")
        begin(**kwargs)
        raise RuntimeError("fixture lost original begin ACK")
    port.begin_fence = lose_begin_ack
    with pytest.raises(RuntimeError, match="lost original begin ACK"):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    row = store._db.execute("SELECT attempt_id,permit_json,receipt_json FROM graph_owner_domain_attempts_v3 "
                            "WHERE operation_id=?", (request["operation_id"],)).fetchone()
    assert row[1:] == (None, None)
    original_permit = port.active
    coordinator._GraphCoordinator__local_module_admission = disabled("d12")
    inspect = port.get_fence_operation
    def inspect_original(**kwargs):
        calls.append("inspect")
        return inspect(**kwargs)
    port.get_fence_operation = inspect_original
    with pytest.raises(LocalModuleAdmissionDeniedV1):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    assert calls == ["begin", "inspect"] and port.active is original_permit
    assert store._db.execute("SELECT permit_json IS NOT NULL,receipt_json FROM graph_owner_domain_attempts_v3 "
                            "WHERE operation_id=?", (request["operation_id"],)).fetchone() == (1, None)
    # The signed-port fixture now reports the same original as finished. No
    # local receipt exists: observing it cannot repair a business commit.
    port.operations[row[0]] = (original_permit, "finished")
    port.active = None
    with pytest.raises(UnavailableGuard, match="not active"):
        coordinator.save_current_creator_draft_for_operation_v1(authority, lease, **request)
    assert calls == ["begin", "inspect", "inspect"]
    assert store._db.execute("SELECT receipt_json FROM graph_owner_domain_attempts_v3 WHERE operation_id=?",
                            (request["operation_id"],)).fetchone() == (None,)


def test_completion_exception_requires_real_originals_instead_of_a_completed_label():
    import sqlite3
    from sylanne3.runtime.local_module_admission_v1 import completed_original_input_v1
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.graph_types import AtomKey, Owner

    db = sqlite3.connect(":memory:")
    ns = NamespaceId("bot", "persona")
    action = AtomKey(Owner("activity", *ns.as_tuple, "activity"), "d08.action_intent.v1", "action").token
    outcome = AtomKey(Owner("activity", *ns.as_tuple, "activity"), "d08.action_outcome.v1", "outcome").token
    db.execute("CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,value TEXT,valid INTEGER)")
    try:
        for kind, request in (
            ("input:register_life_outcome", SimpleNamespace(outcome=SimpleNamespace(plan_original_ref="absent", status="completed"))),
            ("input:register_life_outcome_v2", SimpleNamespace(outcome=SimpleNamespace(plan_original_ref="absent", status="completed"))),
            ("input:record_body_component", SimpleNamespace(component=SimpleNamespace(action_intent_ref=action,
                 action_outcome_ref=outcome, status="completed")))):
            assert completed_original_input_v1(db, ns, kind, request, SimpleNamespace()) is False
        assert db.total_changes == 0
    finally:
        db.close()


def test_completion_classification_gets_a_pinned_read_and_rolls_back_on_refusal(monkeypatch):
    import sqlite3
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.runtime.domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
    from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentLifeOutcomeInputRequestV2
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.runtime import local_module_admission_v1 as admission

    # Observe the real run_current admission closure at the fixed Owner-write
    # seam. This tests pinned-read control flow, not a Life terminal grant.
    graph = object.__new__(GraphCoordinator)
    runtime = object.__new__(InstalledDomainOperationRuntimeV1)
    runtime.graph, runtime._bootstrap = graph, object()
    graph._GraphCoordinator__domain_production_runtime_v1 = runtime
    graph._GraphCoordinator__local_module_admission = disabled("d10", "d12")
    graph._GraphCoordinator__d11_issuer = object()
    db = sqlite3.connect(":memory:", isolation_level=None)
    seen = []
    def original_completion(*args):
        seen.append(db.in_transaction)
        assert db.in_transaction
        assert db.execute("SELECT 1").fetchone() == (1,)
        return True
    def at_owner_write(authority, lease, **kwargs):
        assert not db.in_transaction
        kwargs["new_work_admission"](db)
        assert not db.in_transaction
        return {}
    graph._owner_domain_write_v3 = at_owner_write
    monkeypatch.setattr(admission, "completed_original_input_v1", original_completion)
    authority = SimpleNamespace(namespace=NamespaceId("bot", "persona"), actor="owner")
    args = dict(operation_kind="input:register_life_outcome_v2",
                request=RegisterCurrentLifeOutcomeInputRequestV2("original", None),
                operation_id="operation", activity_id="activity", audience_ref="owner",
                parent_budget_lease_ref="existing-budget")
    try:
        assert runtime.run_current(authority, object(), **args) == {}
        assert seen == [True] and db.total_changes == 0
        def invalid_original(*args):
            assert db.in_transaction
            raise ValueError("actual original changed")
        monkeypatch.setattr(admission, "completed_original_input_v1", invalid_original)
        with pytest.raises(ValueError, match="actual original changed"):
            runtime.run_current(authority, object(), **args)
        assert not db.in_transaction and db.total_changes == 0
    finally:
        db.close()


def test_c04_prepared_running_original_cannot_claim_new_native_work_when_disabled(monkeypatch):
    from sylanne3.graph_coordinator import GraphCoordinator
    from sylanne3.runtime import graph_c04_product_v3 as product
    from sylanne3.runtime_contracts import NamespaceId

    calls = []
    observed = SimpleNamespace(claim=None)
    def inspect(binding):
        calls.append("inspect_original")
        return observed
    def execute(binding):
        calls.append("first_native_execute")
        raise RuntimeError("fixture reached first native execution")
    graph = object.__new__(GraphCoordinator)
    graph._GraphCoordinator__c04_authority_port_v3 = SimpleNamespace(inspect=inspect, execute=execute)
    graph._GraphCoordinator__local_module_admission = LocalModuleAdmissionV1()
    graph._authorize = lambda *args, **kwargs: None
    prepared = SimpleNamespace(binding=SimpleNamespace(binding_digest="a" * 64))
    job = SimpleNamespace(continuation={"schema": "c04.prepared-job-continuation.v4"},
                          phase="running", fence=1, cancel_epoch=0, lease_holder="holder")
    monkeypatch.setattr(product, "_read_original", lambda *args: (prepared, job))
    monkeypatch.setattr(product, "c04_terminal_proof_from_inspection_v3", lambda read: None)
    authority = SimpleNamespace(namespace=NamespaceId("bot", "persona"))
    with pytest.raises(RuntimeError, match="reached first native execution"):
        product.advance_current_c04_product_v3(graph, authority, object(), "operation", holder="holder")
    assert calls == ["inspect_original", "first_native_execute"]
    calls.clear()
    graph._GraphCoordinator__local_module_admission = disabled("d04")
    with pytest.raises(LocalModuleAdmissionDeniedV1) as held:
        product.advance_current_c04_product_v3(graph, authority, object(), "operation", holder="holder")
    assert held.value.operation_kind == "c04:first_native_claim"
    assert held.value.disabled_modules == ("d04",)
    assert calls == ["inspect_original"]
    calls.clear()
    observed.claim = "original_claim_already_exists"
    recovered = product.advance_current_c04_product_v3(graph, authority, object(), "operation", holder="holder")
    assert recovered["status"] == "claim_only_unknown"
    assert recovered["recovery_policy"] == "inspect_original_only" and calls == ["inspect_original"]
