"""Signed-wire and real SQLite budget acceptance, using ephemeral test keys.

The frame source inventory here is synthetic (shared with frame codec tests).
This is not a real provider/tokenizer, production installation, or egress test.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import base64
import json
import os

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_natural_frame_v4 import case
from sylanne3.authority_service.d13_wire_evidence_v1 import (
    D13ForegroundBudgetBindingV1, D13ForegroundBudgetPreparationV1,
    InstalledD13WireEvidencePortV1, InstalledD13WirePolicyV1, SIGNING_DOMAIN,
    _pair_original_fields, _verify_foreground_budget,
    install_d13_wire_evidence_schema_v1, record_signed_d13_wire_evidence_v1,
    verify_signed_d13_wire_envelope_v1,
)
from sylanne3.authority_service.d13_installed_counter_v1 import InstalledD13CounterCommandV1
from sylanne3.runtime import installed_d13_natural_frame_v4 as frame
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, reserve_budget, install_schema as budget_schema
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D02ResourceIssuer, D11BudgetGrantIssuer, ResourceQuote,
    install_schema as issuer_schema,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


def signed(key, payload):
    return {"payload": payload, "signature": base64.b64encode(key.sign(
        SIGNING_DOMAIN + canonical_serialize(payload).encode())).decode()}


def setup(monkeypatch, *, token_fields=None, choice="compressed", allow_conservative_switch=False):
    db, args, state, cache_key = case(monkeypatch)
    import sylanne3.runtime.d13_current_window as reader
    monkeypatch.setattr(reader, "read_current_d13_window_for_authority_v1",
        lambda *a, **kw: replace(state["window"], trusted_utc=a[5]))
    budget_schema(db)
    issuer_schema(db)
    install_d13_wire_evidence_schema_v1(db)
    db.commit()
    db.execute("BEGIN")
    key = Ed25519PrivateKey.generate()
    policy = InstalledD13WirePolicyV1(args["installation"], key.public_key().public_bytes_raw().hex(),
        "test-full-provider-wire-counter", 1, "a" * 64, "b" * 64, "c" * 64,
        1500, 0, 1_000_000, 1_500_000, 2_000_000, 5,
        allow_conservative_switch=allow_conservative_switch)
    d02, d11 = D02ResourceIssuer(os.urandom(32)), D11BudgetGrantIssuer(os.urandom(32))
    ceiling = {"model_tokens": 3000, "model_microusd": 5000}
    ns = args["namespace"]
    create_budget_lease(db, BudgetLease("fg-lease", None, *ns.as_tuple, "USD", ceiling,
        {}, {}, {}, 1, "active"), "create-fg", "a" * 64)
    grant = BudgetLeaseGrant("fg-grant", 1, *ns.as_tuple, "fg-lease", "USD", ceiling,
        ("natural_generation",), 200.0, "fg-policy")
    d11.issue_budget_grant(db, grant)
    prep = D13ForegroundBudgetPreparationV1(ns, "fg-lease", "fg-grant", 1,
        canonical_digest(grant), ceiling, "fg-activity", "fg-reserve")
    port = InstalledD13WireEvidencePortV1(db, policy=policy, foreground_budget=prep,
        resource_issuer=d02, budget_issuer=d11)
    raw, _, no_proof = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
    assert no_proof.budget_state == "unverified" and not raw.input.stable_history
    request = port.pending_count_request
    assert request is not None
    payload = {**request["original"], "token_evidence": "exact_full_wire",
        "raw_lower_tokens": 1100, "raw_upper_tokens": 1100,
        "compressed_lower_tokens": 800, "compressed_upper_tokens": 800}
    payload.update(token_fields or {})
    envelope = signed(key, payload)
    record_signed_d13_wire_evidence_v1(db, policy=policy, envelope=envelope)
    if choice == "hold":
        with pytest.raises(ValueError, match="requires HOLD"):
            frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
        return locals()
    selected, reads, decision = frame.freeze_current_natural_frame_v4(db, **args, installed_wire_port=port)
    assert bool(selected.input.stable_history) == (choice == "compressed")
    assert decision.budget_state == "preparation_only"
    return locals()


def reserve(c, *, snapshot=None, ceiling=None, resource=None):
    db, selected = c["db"], c["selected"]
    ceiling = dict(c["prep"].quote_ceiling) if ceiling is None else ceiling
    snapshot = snapshot or "natural-generation-snapshot:" + canonical_digest({
        "frozen_input_digest": selected.frozen_input_digest,
        "read_versions": [(r.key.token, r.revision) for r in c["reads"]]})[:48]
    from sylanne3.host.authority_profile import installed_model_config_ref
    installed = c["policy"].installation
    resource = resource or installed_model_config_ref(installed.provider_id, installed.model_id, installed.provider_config_digest)
    quote = ResourceQuote("fg-quote", 1, *c["ns"].as_tuple, "fg-activity", "fg-reserve", None,
        "fg-lease", "natural_generation", snapshot, 130.0, resource, None,
        (), (), ceiling, None, 130.0)
    c["d02"].issue_quote(db, quote)
    reserve_budget(db, "fg-lease", "fg-reserve", "d" * 64, ceiling)
    return D13ForegroundBudgetBindingV1("fg-quote", 1, "fg-lease", "fg-reserve", "d" * 64)


def test_signed_original_replay_preserves_time_and_has_atomic_reserved_gate(monkeypatch):
    c = setup(monkeypatch)
    raw, compressed, window, standby, plan, proof = c["port"]._last_pair
    later = replace(window, trusted_utc=101.0)
    expected = _pair_original_fields(c["policy"], raw, compressed, later, standby, plan)
    assert all(c["payload"][k] == v for k, v in expected.items())
    assert verify_signed_d13_wire_envelope_v1(c["policy"], c["envelope"]) == c["payload"]
    binding = reserve(c)
    admitted = c["port"].validate_reserved_selection_v1(selected=c["selected"], decision=c["decision"],
        binding=binding, read_versions=c["reads"], now_utc=101.0)
    assert admitted.budget_state == "reserved_original"
    assert admitted.proof_digest != c["decision"].proof_digest
    assert c["decision"].budget_state == "preparation_only"
    assert admitted.wire_digest == c["selected"].model_request_digest
    assert json.loads(c["db"].execute("SELECT envelope_json FROM graph_d13_wire_evidence_v1").fetchone()[0]) == c["envelope"]


@pytest.mark.parametrize("field,value", [
    ("raw_upper_tokens", 1), ("compressed_upper_tokens", 1),
    ("raw_request_digest", "e" * 64), ("compressed_request_digest", "e" * 64),
    ("original_window_digest", "e" * 64), ("original_standby_digest", "e" * 64),
    ("expires_at_utc", 10000.0), ("frozen_at_utc", 0.0),
])
def test_forged_signed_count_wire_original_or_time_rejected(monkeypatch, field, value):
    c = setup(monkeypatch)
    forged = deepcopy(c["envelope"])
    forged["payload"][field] = value
    with pytest.raises((ValueError, InvalidSignature)):
        verify_signed_d13_wire_envelope_v1(c["policy"], forged)


@pytest.mark.parametrize("changed", ["signature", "key", "model", "config", "tokenizer", "namespace"])
def test_wrong_signature_installed_identity_or_namespace_fails(monkeypatch, changed):
    c = setup(monkeypatch)
    policy, envelope = c["policy"], deepcopy(c["envelope"])
    if changed == "signature":
        envelope["signature"] = base64.b64encode(bytes(64)).decode()
    elif changed == "key":
        policy = replace(policy, counter_public_key_hex=Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex())
    elif changed == "model":
        policy = replace(policy, installation=replace(policy.installation, model_id="other"))
    elif changed == "config":
        policy = replace(policy, installation=replace(policy.installation, provider_config_digest="e" * 64))
    elif changed == "tokenizer":
        policy = replace(policy, tokenizer_fingerprint="e" * 64)
    else:
        envelope["payload"]["namespace"]["persona_id"] = "other"
    with pytest.raises((ValueError, InvalidSignature)):
        verify_signed_d13_wire_envelope_v1(policy, envelope)


@pytest.mark.parametrize("change", ["source", "access", "delete", "generation", "expiry", "budget", "grant"])
def test_current_source_and_budget_change_cannot_reuse_count(monkeypatch, change):
    c = setup(monkeypatch)
    raw, compressed, w, standby, plan, _ = c["port"]._last_pair
    now = 101.0
    if change == "source":
        w = replace(w, turns=(replace(w.turns[0], text="Changed source"), *w.turns[1:]))
    elif change in {"access", "delete", "generation"}:
        field = {"access": "access_epoch", "delete": "delete_epoch", "generation": "activation_epoch"}[change]
        w = replace(w, **{field: getattr(w, field) + 1})
    elif change == "expiry":
        now = 130.0
    elif change == "budget":
        reserve_budget(c["db"], "fg-lease", "competing-reserve", "f" * 64, {"model_tokens": 1})
    else:
        c["db"].execute("UPDATE runtime_budget_grants SET status='revoked'")
    c["state"]["window"] = w
    try:
        result = c["port"].evaluate_natural_pair_v4(raw=raw, compressed=compressed,
            current_window=replace(w, trusted_utc=now), standby=standby,
            precompression_plan=plan, now_utc=now)
    except ValueError:
        result = None
    assert result is None


@pytest.mark.parametrize("change", ["snapshot", "reservation", "ceiling", "resource"])
def test_post_reservation_gate_rejects_wrong_actual_original(monkeypatch, change):
    c = setup(monkeypatch)
    binding = reserve(c, snapshot="wrong-snapshot" if change == "snapshot" else None,
                      ceiling={"model_tokens": 2000, "model_microusd": 4000} if change == "ceiling" else None,
                      resource="provider:other" if change == "resource" else None)
    if change == "reservation":
        binding = replace(binding, reservation_digest="e" * 64)
    with pytest.raises(ValueError):
        c["port"].validate_reserved_selection_v1(selected=c["selected"], decision=c["decision"],
            binding=binding, read_versions=c["reads"], now_utc=101.0)


def test_bound_tag_and_no_fabricated_zero_or_bool_counts(monkeypatch):
    c = setup(monkeypatch)
    bounded = {**c["payload"], "token_evidence": "bounded_full_wire", "raw_lower_tokens": 700}
    assert verify_signed_d13_wire_envelope_v1(c["policy"], signed(c["key"], bounded))["raw_lower_tokens"] == 700
    for bad in (True, -1, 0.5):
        with pytest.raises(ValueError):
            verify_signed_d13_wire_envelope_v1(c["policy"], signed(c["key"], {**bounded, "compressed_lower_tokens": bad}))
    assert verify_signed_d13_wire_envelope_v1(c["policy"], signed(c["key"], {**bounded, "compressed_lower_tokens": 0}))["compressed_lower_tokens"] == 0
    with pytest.raises(ValueError):
        verify_signed_d13_wire_envelope_v1(c["policy"], signed(c["key"], {**bounded, "compressed_upper_tokens": 0}))
    with pytest.raises(ValueError):
        verify_signed_d13_wire_envelope_v1(c["policy"], signed(c["key"], {**bounded, "token_evidence": "exact_full_wire"}))


def test_counter_cannot_execute_inside_graph_transaction(monkeypatch):
    c = setup(monkeypatch)
    command = InstalledD13CounterCommandV1("/not-installed/counter", "1" * 64)
    with pytest.raises(ValueError, match="forbidden inside"):
        command.count_outside_graph_transaction_v1(db=c["db"], policy=c["policy"], request=c["request"])


def test_missing_installed_capability_stays_raw_unverified(monkeypatch):
    from sylanne3.runtime.installed_d13_wire_evidence_v1 import build_installed_d13_wire_evidence_port_v1
    c = setup(monkeypatch)
    assert build_installed_d13_wire_evidence_port_v1(c["db"], policy=None, foreground_budget=None,
        resource_issuer=None, budget_issuer=None) is None
    result, _, decision = frame.freeze_current_natural_frame_v4(c["db"], **c["args"])
    assert not result.input.stable_history
    assert decision.budget_state == "unverified"
    assert decision.token_evidence == "token_evidence_unverified"


def test_compressed_original_rejects_reused_preparation_port(monkeypatch):
    c = setup(monkeypatch)
    c["db"].execute("UPDATE graph_atoms SET revision=2,value=? WHERE token=?",
        (json.dumps(c["decision"].activation_write.value), c["cache_key"].token))
    with pytest.raises(ValueError, match="full-wire proof unavailable"):
        frame.freeze_current_natural_frame_v4(c["db"], **dict(c["args"], now_utc=101.0),
            installed_wire_port=c["port"], original=c["selected"])


@pytest.mark.parametrize("raw_low,raw_high,compressed_high,allow,choice", [
    (600, 900, 700, False, "raw"),
    (1000, 1100, 800, False, "compressed"),
    (0, 1100, 800, True, "compressed"),
    (0, 1100, 800, False, "hold"),
    (1000, 1100, 1000, True, "hold"),
])
def test_bounded_full_wire_selection_keeps_raw_or_holds_without_invented_pressure(
        monkeypatch, raw_low, raw_high, compressed_high, allow, choice):
    c = setup(monkeypatch, token_fields={"token_evidence": "bounded_full_wire",
        "raw_lower_tokens": raw_low, "raw_upper_tokens": raw_high,
        "compressed_lower_tokens": 600, "compressed_upper_tokens": compressed_high},
        allow_conservative_switch=allow, choice=choice)
    assert c["port"]._last_pair[-1].selected == choice
