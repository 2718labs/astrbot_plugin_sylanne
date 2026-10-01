"""Offline installed-counter seam through the real fenced Graph entrypoint.

D13 history inventory and provider counting are explicit synthetic seams. The
C02/D09 inputs, Graph write fence, signed foreground quote/grant/reservation,
selected original, cache CAS and acquire/recheck are real product code.
"""
from dataclasses import asdict, replace
from types import SimpleNamespace
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.d13_wire_evidence_v1 import InstalledD13WirePolicyV1, SIGNING_DOMAIN
from sylanne3.authority_service.d13_installed_counter_v1 import InstalledD13CounterCommandV1
from sylanne3.domains.d13.provider import D13ShortContextProvider, block_graph_value
from sylanne3.domains.d13.precompression import compile_deterministic_candidate
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import source_key, access_key
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from sylanne3.runtime.d13_precompression_job import prepare_precompression_intent_v1
from sylanne3.runtime.jobs import create_job, get_job
from sylanne3.runtime_contracts import (
    AuthorityContext, CompletedTurnV1, ConversationWindowProjectionV1, VersionedRef,
    canonical_digest, canonical_serialize,
)
from test_context_reply_prepare_v2 import _context_reply_original_paid_lifecycle_case
from test_context_reply_prepare_v2 import context_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401
import test_first_ingress_c02_commit


@pytest.fixture
def installed_case(monkeypatch, request):
    original_scene = test_first_ingress_c02_commit._scene_case
    def scene(*args, **kwargs):
        import test_graph_v2_provisioning
        base_policy = test_graph_v2_provisioning.policy_for
        def policy_with_foreground_ceiling(store):
            value = base_policy(store)
            return replace(value,
                root_lease=replace(value.root_lease, limits={**value.root_lease.limits,
                    "input_tokens": 20000, "model_microusd": 40000}),
                root_grant=replace(value.root_grant, max_ceiling={**value.root_grant.max_ceiling,
                    "input_tokens": 10000, "model_microusd": 20000}))
        monkeypatch.setattr(test_graph_v2_provisioning, "policy_for", policy_with_foreground_ceiling)
        kwargs["extra_specs"] = tuple(kwargs.get("extra_specs", ())) + D13ShortContextProvider().register_types()
        return original_scene(*args, **kwargs)
    monkeypatch.setattr(test_first_ingress_c02_commit, "_scene_case", scene)
    original = request.getfixturevalue("context_reply_c02_case")
    case = _context_reply_original_paid_lifecycle_case(original, monkeypatch, stop_before_paid=True)
    store, graph, ns = case["store"], case["graph"], case["namespace"]
    db = store._db
    account = json.loads(db.execute("SELECT value FROM graph_atoms WHERE type_name='d03.account_binding'").fetchone()[0])
    now = account["valid_from"] + 1.0
    with store._lock:
        db.execute("BEGIN")
        try:
            epoch = graph._v2_graph_stamp(ns)[1]
            current = graph._current_natural_generation_inputs_locked(ns, case["c02"].operation_id,
                case["source_ref"], now, epoch)
        finally:
            db.rollback()
    scene_ref, audience_ref, conversation = current[7], current[8], current[2].conversation_ref
    source_template = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?", (case["source_ref"],)).fetchone()[0])
    question_id = AtomKey.from_token(case["source_ref"]).owner.subject
    access_template = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?", (access_key(*ns.as_tuple, question_id).token,)).fetchone()[0])
    turns = []
    def insert(key, value):
        db.execute("INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,revision,value,valid) "
            "VALUES(?,?,?,?,?,?,?,1,?,1)", (key.token, *ns.as_tuple, key.owner.kind, key.owner.subject,
                key.type_name, key.name, canonical_serialize(value)))
    with store._lock:
        db.execute("BEGIN")
        for i in range(6):
            sid = "d13-offline-source:" + str(i)
            skey, akey = source_key(*ns.as_tuple, sid), access_key(*ns.as_tuple, sid)
            text = "Keep this detail. Another useful sentence. " + "x" * 180
            insert(skey, {**source_template, "source_id": sid, "text": text})
            insert(akey, access_template)
            sr, ar = VersionedRef(skey.token, 1), VersionedRef(akey.token, 1)
            turns.append(CompletedTurnV1(conversation, audience_ref, i, sr, sr, ar,
                "fixture-speaker", text, now - 60 + i, "confirmed", "not_applicable"))
        rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        deps = tuple(dict.fromkeys(r for t in turns for r in (t.raw_ref, t.source_ref, t.access_ref)))
        window = ConversationWindowProjectionV1(ns, "owner:fixture", conversation, scene_ref, audience_ref,
            tuple(turns), 5, now, deps, (scene_ref, audience_ref, *deps), *rights, 1)
        intent = prepare_precompression_intent_v1(window, history_token_budget=2000,
            background_capacity=True, outstanding_candidate=False, attempted_input_digests=frozenset(),
            parent_budget_lease_ref=case["installed"].installation_policy.root_lease.lease_id,
            resource_ref="d13:cpu", ceiling={"d13_compute_units": 1}, deadline_utc=now + 200)
        assert intent is not None
        block = replace(compile_deterministic_candidate(window, intent.plan), status="standby")
        cache_key = AtomKey(Owner("persona", *ns.as_tuple), "d13.compressed_turn_block.v2", block.block_ref)
        insert(cache_key, block_graph_value(block))
        create_job(db, replace(intent.job, phase="completed", result_ref=block.block_ref),
            "fixture-create-standby-job", "a" * 64)
        original_policy = case["installed"].installation_policy
        grant = original_policy.root_grant
        db.commit()
    policy = original_policy
    base = case["installed"].model_workflows.context_reply
    generation = replace(base, work_kind="natural_generation", template_version=TEMPLATE_VERSION,
        quote_ceiling={"input_tokens": 2000, "output_tokens": 16, "model_microusd": 5000})
    review = replace(base, work_kind="natural_review", template_version=REVIEW_TEMPLATE_VERSION)
    key = Ed25519PrivateKey.generate()
    wire_policy = InstalledD13WirePolicyV1(NaturalReplyInstallationV2(policy.installation_id,
        generation.provider_config_digest, generation.provider_id, generation.model_id, generation.max_output_tokens),
        key.public_key().public_bytes_raw().hex(), "offline-fixture-counter", 1,
        "b" * 64, "c" * 64, "d" * 64, 1400, 0, 1_000_000, 1_000_000, 1_000_000, 0)
    installed = replace(case["installed"], installation_policy=policy,
        model_workflows=replace(case["installed"].model_workflows, natural_generation=generation, natural_review=review),
        d13_wire_policy=wire_policy, d13_wire_counter=InstalledD13CounterCommandV1("/fixture-only/counter", "e" * 64))
    state = {"window": window, "now": now, "calls": [], "fail": None}
    import sylanne3.runtime.d13_current_window as source_reader
    import sylanne3.runtime.installed_d13_natural_frame_v4 as frame
    def current_window(*args, **kwargs):
        return replace(state["window"], trusted_utc=args[5])
    monkeypatch.setattr(source_reader, "read_current_d13_window_for_authority_v1", current_window)
    monkeypatch.setattr(frame, "read_current_d13_window_for_authority_v1", current_window)
    port = case["owner_scene_case"][2]
    monkeypatch.setattr(port, "read_ingress_clock", lambda policy: SimpleNamespace(
        utc_upper_bound_seconds=state["now"], monotonic_after_seconds=time.monotonic()))
    monkeypatch.setattr(port, "natural_paid_consumer_ready_v2", lambda **kwargs: kwargs["template_version"] == TEMPLATE_VERSION, raising=False)
    def count(self, *, db, policy, request):
        assert not db.in_transaction and not store._lock._is_owned()
        state["calls"].append(request)
        state["now"] += 1.0
        if state["fail"] == "counter":
            raise ValueError("offline counter failed")
        if state["fail"] == "source":
            state["window"] = replace(state["window"], delete_epoch=state["window"].delete_epoch + 1)
        payload = {**request["original"], "token_evidence": "exact_full_wire",
            "raw_lower_tokens": 1500, "raw_upper_tokens": 1500,
            "compressed_lower_tokens": 1000, "compressed_upper_tokens": 1000}
        return {"payload": payload, "signature": base64.b64encode(key.sign(
            SIGNING_DOMAIN + canonical_serialize(payload).encode())).decode()}
    monkeypatch.setattr(InstalledD13CounterCommandV1, "count_outside_graph_transaction_v1", count)
    return {**case, **locals(), "case": case["case"]}


def test_real_prepare_counts_outside_sql_then_seals_active_target_and_retries_once(installed_case, tmp_path):
    c = installed_case
    graph, db, ns = c["graph"], c["db"], c["ns"]
    args = (c["case"][2], ns, c["c02"].operation_id, c["source_ref"], c["installed"])
    saved = graph.prepare_post_c02_natural_generation_v2(*args)
    assert len(c["state"]["calls"]) == 1
    assert saved.frozen.input.frozen_at_utc == c["state"]["calls"][0]["original"]["frozen_at_utc"]
    assert saved.frozen.input.frozen_at_utc < c["state"]["now"]
    assert c["state"]["now"] == c["now"] + 1
    assert saved.frozen.input.stable_history
    assert saved.frozen.input.history_selection.block_ref.version == 2
    assert next(r.revision for r in saved.read_versions if r.key == c["cache_key"]) == 2
    job = get_job(db, saved.seal.job_id)
    assert job.continuation["history_budget_state"] == "reserved_original"
    assert job.continuation["history_proof_digest"] != job.continuation["history_preparation_proof_digest"]
    assert db.execute("SELECT revision,json_extract(value,'$.status') FROM graph_atoms WHERE token=?", (c["cache_key"].token,)).fetchone() == (2, "active")
    assert graph.prepare_post_c02_natural_generation_v2(*args) == saved
    assert len(c["state"]["calls"]) == 1
    grant = c["policy"].root_grant
    worker_lease, capability = graph.grant(c["case"][2], actor=c["policy"].administrator_holder,
        issuer_domain="d11", namespace=ns, domains=("d11",), activation_generation=1,
        operation_id=saved.seal.acquire_operation_id)
    worker = AuthorityContext(c["policy"].administrator_holder, "d11", capability, ns,
        ("activity",), "proposal", (c["conversation"],), c["generation"].provider_config_ref, 1)
    acquired, request = graph.acquire_post_c02_natural_generation_v2(worker, worker_lease,
        c["c02"].operation_id, c["installed"], lease_seconds=60)
    assert acquired.phase == "running" and request.call_id == saved.seal.call_id
    # Exercise the real independent Authority admission graph check as well.
    # This checks eligibility only; it does not invoke admission or a provider.
    import sqlite3
    from sylanne3.authority_service.d13_natural_frame_verifier_v1 import build_authority_d13_natural_frame_verifier_v1
    from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
    from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
    from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
    actual_request, draft, anchor = graph.read_natural_model_egress_preparation_v2(
        replace(worker, worker_fence=acquired.fence), worker_lease,
        c["c02"].operation_id, "generation", c["installed"])
    assert actual_request == request
    authority_db = sqlite3.connect(tmp_path / "model-authority.sqlite", isolation_level=None)
    authority_db.execute("PRAGMA synchronous=FULL")
    model_store = AuthorityV2ModelEgressStore(authority_db, create=True)
    history = build_authority_d13_natural_frame_verifier_v1(bundle=c["installed"],
        d11_issuer=graph._GraphCoordinator__d11_issuer, authority_store=model_store)
    verifier = PinnedCurrentModelEgressGraphVerifier(db.execute("PRAGMA database_list").fetchone()[2],
        d11_issuer=graph._GraphCoordinator__d11_issuer,
        trusted_now_utc=lambda: c["state"]["now"] + 0.01,
        trusted_paired_clock=lambda: (c["state"]["now"] + 0.01, "fixture-clock-epoch"),
        natural_history_verifier=history)
    egress = ModelEgressIntentV1(**asdict(draft), fence_token="f" * 32, fence_epoch=1,
        fence_revision=0, anchor_digest=canonical_digest(asdict(anchor)))
    assert verifier.complete_graph_current(egress)
    with c["store"]._lock:
        db.execute("UPDATE graph_atoms SET revision=3 WHERE token=?", (c["cache_key"].token,))
    assert not verifier.complete_graph_current(egress)
    graph.release_authority_lease(c["case"][2], worker_lease)
    authority_db.close()


@pytest.mark.parametrize("failure", ["counter", "source", "reserve"])
def test_preflight_failure_closes_attempt_without_half_activation_or_reservation(installed_case, failure, monkeypatch):
    c = installed_case
    c["state"]["fail"] = failure
    if failure == "reserve":
        import sylanne3.runtime.installed_d13_wire_evidence_v1 as wire
        original = wire.validate_reserved_d13_natural_selection_v1
        def after_reservation(*args, **kwargs):
            admitted = original(*args, **kwargs)
            assert admitted.budget_state == "reserved_original"
            raise ValueError("injected failure after actual signed reservation guard")
        monkeypatch.setattr(wire, "validate_reserved_d13_natural_selection_v1", after_reservation)
    with pytest.raises(Exception):
        c["graph"].prepare_post_c02_natural_generation_v2(c["case"][2], c["ns"],
            c["c02"].operation_id, c["source_ref"], c["installed"])
    assert c["db"].execute("SELECT revision,json_extract(value,'$.status') FROM graph_atoms WHERE token=?", (c["cache_key"].token,)).fetchone() == (1, "standby")
    assert c["db"].execute("SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='natural_generation'").fetchone() == (0,)
    assert c["db"].execute("SELECT COUNT(*) FROM graph_d13_wire_evidence_v1").fetchone() == (0,)
    assert c["db"].execute("SELECT COUNT(*) FROM runtime_budget_reservations WHERE operation_id LIKE 'natural-generation-reservation:%'").fetchone() == (0,)
    assert c["db"].execute("SELECT state FROM graph_natural_generation_attempts_v2").fetchone() == ("closed",)
