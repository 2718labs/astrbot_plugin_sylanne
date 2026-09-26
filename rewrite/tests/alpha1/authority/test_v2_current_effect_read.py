"""A current effect read requires both Authority and exact append evidence."""

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import PlatformObservationV1
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime_contracts import NamespaceId

from test_execution_binding_v2_claim import AUTH_NS, _binding_v2, _prepared, _service


OTHER_AUTH_NS = namespace_ref(NamespaceId("other-bot", "persona"))


def test_absent_and_exact_prepared_then_claimed_effect(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    absent = bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a")
    assert absent == CurrentEffectReadV2(
        authority_id=absent.authority_id, namespace=AUTH_NS, effect_id="effect-a",
        activation_generation=1, state="absent", execution_head_seq=0,
        execution_head_digest="genesis")
    prepared, origin = _prepared(core, fences, bridge)
    current = bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a")
    assert (current.state, current.effect_seq, current.execution_head_seq) == (
        "unresolved", 1, 1)
    assert current.append_digest == prepared.after_anchor.execution_digest
    assert current.mutation_id == prepared.pending.mutation_id
    assert current.observation_id is None
    assert bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="other-effect").state == "absent"

    claimed, _ = bridge.execution_claim_v2(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=_binding_v2(origin))
    current = bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a")
    assert (current.state, current.effect_seq, current.execution_head_seq) == (
        "unresolved", 2, 2)
    assert current.append_digest == claimed.after_anchor.execution_digest
    core.close()
    journal.close()


def test_stale_head_and_missing_or_tampered_index_fail_closed(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, _ = _prepared(core, fences, bridge)
    with core._tx() as db:
        db.execute("UPDATE authority_namespaces SET execution_digest=? WHERE namespace=?",
                   ("sha256:" + "f" * 64, AUTH_NS))
    with pytest.raises(AuthorityUnavailable, match="execution journal differs"):
        bridge.read_current_effect(
            credential="ok", subject="subject-a", effect_id="effect-a")
    with core._tx() as db:
        db.execute("UPDATE authority_namespaces SET execution_digest=? WHERE namespace=?",
                   (prepared.after_anchor.execution_digest, AUTH_NS))
        db.execute("DELETE FROM authority_effects WHERE namespace=? AND effect_id=?",
                   (AUTH_NS, "effect-a"))
    with pytest.raises(AuthorityUnavailable, match="index and append history"):
        bridge.read_current_effect(
            credential="ok", subject="subject-a", effect_id="effect-a")
    with core._tx() as db:
        db.execute("INSERT INTO authority_effects VALUES(?,?,?,?,?)",
                   (AUTH_NS, "effect-a", "unresolved", "[]", 1))
    with pytest.raises(AuthorityUnavailable, match="conflict evidence"):
        bridge.read_current_effect(
            credential="ok", subject="subject-a", effect_id="effect-a")
    core.close()
    journal.close()


def test_verified_observation_reports_only_observed_evidence(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    prepared, origin = _prepared(core, fences, bridge)
    claimed, _ = bridge.execution_claim(
        credential="ok", subject="subject-a", prepared_receipt=prepared,
        binding=origin)
    observation = PlatformObservationV1(
        binding=origin, handoff_start_ref="handoff-a",
        adapter_ref=origin.adapter_ref, account_ref=origin.account_ref,
        destination_ref=origin.destination_ref,
        observation_id="observation-a", platform_request_id=None,
        platform_message_id=None, evidence_source_ref="adapter-evidence-a",
        outcome="unknown", status_code_summary=None,
        observed_at_utc="2026-09-24T01:02:03Z", time_source_ref="clock-a")
    bridge._observation_verifier = lambda namespace, receipt, report: report
    observed, _ = bridge.execution_observe(
        credential="ok", subject="subject-a", claimed_receipt=claimed,
        observation=observation)
    current = bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a")
    assert (current.state, current.effect_seq, current.observation_id) == (
        "observed", 3, "observation-a")
    assert current.append_digest == observed.after_anchor.execution_digest
    assert not hasattr(current, "outcome")
    core.close()
    journal.close()


def test_namespace_and_authorization_do_not_leak_effect(tmp_path):
    core, fences, journal, bridge = _service(tmp_path)
    with pytest.raises(AuthorityUnavailable, match="authentication denied"):
        bridge.read_current_effect(
            credential="bad", subject="subject-a", effect_id="effect-a")
    with core._tx() as db:
        db.execute(
            "INSERT INTO authority_namespaces "
            "SELECT ?,holder,generation,phase,transfer_id,target,"
            "revocation_epoch,deletion_journal_id,deletion_seq,deletion_digest,"
            "deletion_phase,execution_journal_id,execution_seq,execution_digest,"
            "anchor_nonce FROM authority_namespaces WHERE namespace=?",
            (OTHER_AUTH_NS, AUTH_NS))
        db.execute("INSERT INTO authority_effects VALUES(?,?,?,?,?)",
                   (OTHER_AUTH_NS, "effect-a", "unresolved", "[]", 1))
    assert bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a").state == "absent"
    _prepared(core, fences, bridge)
    assert bridge.read_current_effect(
        credential="ok", subject="subject-a", effect_id="effect-a").effect_seq == 1
    core.close()
    journal.close()
