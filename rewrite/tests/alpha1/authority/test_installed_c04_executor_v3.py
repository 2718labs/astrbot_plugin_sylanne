"""V3 completed terminal output is bound to exact input, build and result."""

from dataclasses import replace
import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.installed_c04_executor_v3 import (
    ALGORITHM_ID, decode_completed_c04_output_v3,
)
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalV2, claim_internal_work_v1,
)
from sylanne3.authority_service.internal_work_contract import _phase_id
from sylanne3.contracts import canonical_json
from sylanne3.domains.d06.c04_work_algorithm_v3 import activate_association_work_v3
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.graph_coordinator import namespace_ref
from tests.alpha1.contracts.test_c04_v3_contracts import work


def _binding(frozen):
    reservation = AtomKey(Owner("activity", "bot", "persona", "activity"),
                          "d02.reservation.v1", "reservation").token
    return InternalWorkBindingV1(
        namespace_ref(frozen.namespace), frozen.activity_id, frozen.operation_id,
        "execution", frozen.input_digest.removeprefix("sha256:"),
        "resource-quote", 1, "b" * 64, "body-quote", 1, "c" * 64,
        reservation, "association-component", "budget", 1,
        ALGORITHM_ID, "body-policy",
        frozen.algorithm_build_digest.removeprefix("sha256:"),
    )


def _terminal(binding, result):
    output = canonical_json({
        "schema": "sylanne.d06.association-work-terminal-output.v3",
        "algorithm_id": ALGORITHM_ID,
        "algorithm_build_digest": result.algorithm_build_digest,
        "input_digest": result.input_digest,
        "result_digest": result.result_digest,
        "result_json": result.to_json(),
    })
    claim = claim_internal_work_v1(binding)
    return InternalWorkTerminalV2(
        binding.binding_digest, claim.mutation_id,
        _phase_id(binding.binding_digest, "terminal"),
        "completed", 1, ALGORITHM_ID, binding.algorithm_build_digest,
        binding.input_digest, result.result_digest.removeprefix("sha256:"),
        output, "internal-work:component:" + binding.binding_digest,
        "d" * 64, "e" * 64, "f" * 64,
    )


def test_completed_terminal_decoder_rejects_wrong_result_or_build():
    frozen = work()
    result = activate_association_work_v3(frozen)
    binding = _binding(frozen)
    terminal = _terminal(binding, result)
    assert decode_completed_c04_output_v3(binding, terminal) == result
    envelope = json.loads(terminal.output_json)
    envelope["result_json"] = replace(result, stop_reason="forged").to_json()
    with pytest.raises(AuthorityUnavailable, match="malformed"):
        decode_completed_c04_output_v3(
            binding, replace(terminal, output_json=canonical_json(envelope)))
    with pytest.raises(AuthorityUnavailable, match="identity"):
        decode_completed_c04_output_v3(
            replace(binding, algorithm_build_digest="0" * 64), terminal)
