"""Clock-unit regression only; no provider, storage or authority admission is simulated."""
from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.d07_current_execution_v1 import (
    D07CognitionResultReadRequestV1, D07CognitionResultReadV1,
)
from sylanne3.authority_service.d07_model_timing_v1 import D07ModelTimingOriginalV1
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.runtime.clock import CharacterClockMapping
from sylanne3.runtime.d07_current_behavior_v1 import D07ExecutionOriginalV1, _activity
from sylanne3.runtime.d07_execution_v1 import require_actual_d07_execution_wall_deadline_v1
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


WALL_START = datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()


def result_clock_inputs(end):
    namespace = NamespaceId("bot", "persona")
    request = D07CognitionResultReadRequestV1(
        "authority", "authority-scope", namespace, "installation", "job", "acquire",
        "operation", "call", "1" * 64, "2" * 64, "consumer", "attempt")
    observation = ModelEgressObservationV1("authority", "authority-scope", "host",
        "egress", "call", "2" * 64, "completed", '{"text":"bounded"}', (), (), None)
    terminal = ModelTerminalReceiptV2("3" * 64, "call", "2" * 64, "4" * 64,
        observation.digest, "sha256:" + "5" * 64, "installation", "6" * 64)
    timing = D07ModelTimingOriginalV1("call", "3" * 64, "2" * 64, "1" * 64,
        WALL_START, end, canonical_digest(asdict(terminal)))
    result = D07CognitionResultReadV1(request, observation, terminal, timing)
    prepared = SimpleNamespace(namespace=namespace, job_id="job", call_id="call",
        operation_id="operation", digest="1" * 64, activity_id="activity", effect_id="effect")
    job = SimpleNamespace(bot_id="bot", persona_id="persona", job_id="job",
        operation_id="operation", activity_id="activity", effect_id="effect",
        deadline_utc="2030-01-01T00:00:10Z")
    return prepared, result, job


@pytest.mark.parametrize("origin,rate", [("9000000000", "2"), ("0", "0.5")])
def test_role_clock_origin_and_rate_do_not_become_utc_deadline(origin, rate):
    prepared, result, job = result_clock_inputs(WALL_START + 5)
    require_actual_d07_execution_wall_deadline_v1(prepared, result, job)
    mapping = CharacterClockMapping("clock", 1, "2030-01-01T00:00:00Z",
        Decimal(origin), Decimal(rate), "2030-01-01T00:00:00Z",
        "2030-01-01T00:01:00Z", "clock-policy", "d11")
    start, end = (float(mapping.character_at(wall)) for wall in
        ("2030-01-01T00:00:00Z", "2030-01-01T00:00:05Z"))
    execution = D07ExecutionOriginalV1("terminal", "operation", "activity", "effect",
        "attempt", "execution", "7" * 64, "8" * 64, "concern", start, end,
        "clock", "1", "budget", ("cost",), ("source",), 1)
    envelope = SimpleNamespace(identity=SimpleNamespace(operation_id="operation",
        activity_id="activity", effect_id="effect", attempt_id="attempt"),
        authority=SimpleNamespace(namespace=prepared.namespace, activation_generation=1),
        parent_budget_lease_ref="budget", deadline_utc=WALL_START + 10)
    write = _activity(envelope, execution, "bounded_concern_segment_completed")
    assert write.value["started_at"] == start
    assert write.value["ended_at"] == end


@pytest.mark.parametrize("end,current_deadline", [
    (WALL_START + 11, None),
    (WALL_START + 11, WALL_START + 20),
    (WALL_START + 5, WALL_START + 4),
])
def test_actual_wall_deadline_uses_original_or_earlier_current_limit(end, current_deadline):
    prepared, result, job = result_clock_inputs(end)
    with pytest.raises(ValueError, match="actual model wall end"):
        require_actual_d07_execution_wall_deadline_v1(prepared, result, job,
            deadline_utc=current_deadline)
    assert job.deadline_utc == "2030-01-01T00:00:10Z"


def test_actual_wall_timing_cannot_be_borrowed_from_another_job():
    prepared, result, job = result_clock_inputs(WALL_START + 5)
    job.effect_id = "other-effect"
    with pytest.raises(ValueError, match="exact original prepared execution/job"):
        require_actual_d07_execution_wall_deadline_v1(prepared, result, job)
