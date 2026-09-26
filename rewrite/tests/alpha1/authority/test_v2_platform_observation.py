"""V2 platform reports bind the durable handoff and original claim."""

from dataclasses import replace
import json

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import (
    DispatchGraphClaimReceiptV1, PlatformObservationV2,
    canonical_digest, from_wire, to_wire,
)
from sylanne3.authority_service.v2_execution_bridge import handoff_start_digest_v2

from test_execution_binding_v2_claim import (
    _binding_v2, _digest, _prepared, _service,
)


def _ready(tmp_path):
    def graph_claim(context, binding, _claimed, _owner, _snapshot):
        return DispatchGraphClaimReceiptV1(
            canonical_digest(context), binding.graph_namespace,
            binding.graph_incarnation, "graph-version-b", 4, 2, 0,
            "graph-claim-a", _digest("8"), "graph-issuer-a")
    core, fences, journal, bridge = _service(
        tmp_path, with_owner=True, final_authorizer=graph_claim,
        final_issuer="graph-issuer-a")
    prepared, origin = _prepared(core, fences, bridge)
    binding = _binding_v2(origin)
    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=binding)
    start = bridge.begin_handoff_v2(
        credential="ok", subject="subject-a", claimed_receipt=claimed,
        handoff_id="handoff-a")
    return core, journal, bridge, claimed, start, binding


def _report(start, binding, *, outcome="accepted", message_id="17"):
    return PlatformObservationV2(
        binding, start.handoff_id, handoff_start_digest_v2(start),
        binding.origin.adapter_ref, binding.origin.account_ref,
        binding.origin.destination_ref, "observation-a", None, message_id,
        "onebot-ack-a", outcome, "2026-09-27T01:00:00Z", "clock-a")


def test_v2_handoff_observation_is_durable_and_replay_is_exact(tmp_path):
    core, journal, bridge, claimed, start, binding = _ready(tmp_path)
    try:
        permit, anchor, effect = bridge.read_current_dispatch_handoff(
            credential="ok", subject="subject-a", start=start,
            claimed_receipt=claimed)
        assert permit == start.permit
        assert anchor == permit.pinned_anchor
        assert effect.state == "unresolved"
        assert effect.execution_head_seq == anchor.execution_seq
        report = _report(start, binding)
        assert from_wire(to_wire(report)) == report
        bridge._observation_verifier = lambda namespace, receipt, value: value
        receipt, _ = bridge.execution_observe_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, observation=report)
        assert receipt.pending.platform_observation == report
        assert receipt.pending.phase == "observed"
        assert bridge.execution_observe_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, observation=report)[0] == receipt
        assert journal.verified_head().seq == 3
        assert bridge.read_current_effect(
            credential="ok", subject="subject-a", effect_id="effect-a"
        ).observation_id == report.observation_id
        with pytest.raises(AuthorityUnavailable, match="no longer current"):
            bridge.read_current_dispatch_handoff(
                credential="ok", subject="subject-a", start=start,
                claimed_receipt=claimed)
        with pytest.raises(AuthorityUnavailable, match="different evidence"):
            bridge.execution_observe_v2(
                credential="ok", subject="subject-a",
                claimed_receipt=claimed,
                observation=replace(report, platform_message_id="18"))
    finally:
        core.close()
        journal.close()
    core, _, journal, bridge = _service(
        tmp_path, create=False, with_owner=True,
        final_authorizer=lambda *_: None, final_issuer="graph-issuer-a")
    try:
        # A committed report replays from Core+journal without calling the
        # live platform verifier or creating another observation.
        replayed, _ = bridge.execution_observe_v2(
            credential="ok", subject="subject-a",
            claimed_receipt=claimed, observation=report)
        assert replayed == receipt
        assert journal.verified_head().seq == 3
    finally:
        core.close()
        journal.close()


def test_v2_report_needs_original_start_and_verifier(tmp_path):
    core, journal, bridge, claimed, start, binding = _ready(tmp_path)
    try:
        report = _report(start, binding)
        with pytest.raises(AuthorityUnavailable, match="verifier"):
            bridge.execution_observe_v2(
                credential="ok", subject="subject-a",
                claimed_receipt=claimed, observation=report)
        bridge._observation_verifier = lambda namespace, receipt, value: value
        with pytest.raises(AuthorityUnavailable, match="start digest"):
            bridge.execution_observe_v2(
                credential="ok", subject="subject-a",
                claimed_receipt=claimed,
                observation=replace(report, start_digest=_digest("f")))
        with pytest.raises(ValueError, match="positive message ID"):
            replace(report, platform_message_id=None)
        with pytest.raises(ValueError, match="invalid account_ref"):
            replace(binding.origin, account_ref='["onebot", "name","bot"]')
        assert journal.verified_head().seq == 2
    finally:
        core.close()
        journal.close()


def test_canonical_astrbot_route_refs_are_accepted_without_other_id_widening(tmp_path):
    core, journal, bridge, _, _, binding = _ready(tmp_path)
    try:
        account = json.dumps(["aiocqhttp", "账号", "123"], ensure_ascii=True,
                             separators=(",", ":"))
        destination = json.dumps(["friend:123", "session:456"],
                                 ensure_ascii=True, separators=(",", ":"))
        assert replace(binding.origin, account_ref=account,
                       destination_ref=destination).account_ref == account
        for value in ('["a", "b","c"]', '["a","b"]', '["a","","c"]'):
            with pytest.raises(ValueError, match="invalid account_ref"):
                replace(binding.origin, account_ref=value)
        with pytest.raises(ValueError, match="invalid destination_ref"):
            replace(binding.origin, destination_ref='["a","b","c"]')
        with pytest.raises(ValueError, match="invalid adapter_ref"):
            replace(binding.origin, adapter_ref='["a","b"]')
    finally:
        core.close()
        journal.close()
