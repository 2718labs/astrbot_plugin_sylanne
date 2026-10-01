"""Installed full-wire verifier reopens the actual current Graph source reader."""
from dataclasses import replace
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.authority_service.d13_wire_evidence_v1 import InstalledD13WirePolicyV1, _verify_current_window
from sylanne3.domains.d09 import ClaimKind
from sylanne3.domains.d09.natural_reply import NaturalExpressionPlanV2, QualifiedExpressionUnitV2
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.model_broker.context_reply import ContextReplyPartV1
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.runtime.installed_d13_natural_frame_v4 import build_natural_frame_v4, POLICY_REF
from sylanne3.runtime_contracts import VersionedRef, canonical_digest
from test_d13_current_conversation_window_v1 import _committed
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401


def test_actual_current_source_access_and_namespace_closure(canonical_private_case, tmp_path):
    store, graph, _, namespace, installed_policy, *_ = canonical_private_case
    receipt, reader, lease, _source_id = _committed(canonical_private_case)
    import json
    scene_id = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?",
        (receipt.slot_ref,)).fetchone()[0])["scene_ref"]
    window = graph.read_current_d13_conversation_window_v1(reader, lease, scene_ref=scene_id, max_slots=4)
    unit = QualifiedExpressionUnitV2("source-quote", ClaimKind.REPORTED_CLAIM, window.turns[0].text,
        window.turns[0].source_ref, (window.turns[0].source_ref,), (window.turns[0].access_ref,), (),
        window.conversation_ref, "expression", window.trusted_utc + 30)
    plan = NaturalExpressionPlanV2(namespace,
        VersionedRef(AtomKey(Owner("activity", *namespace.as_tuple, "wire-test"), "plan.test", "current").token, 1),
        window.scene_ref, window.audience_ref, ("reply",), ("paraphrase",), (), (unit,),
        window.trusted_utc + 30, "activity", "operation", "effect", scene_id, window.conversation_ref)
    question = ContextReplyPartV1("question", window.turns[0].source_ref, window.audience_ref,
        window.trusted_utc + 30, window.turns[0].text)
    installation = NaturalReplyInstallationV2(installed_policy.installation_id, "a" * 64, "provider", "model", 32)
    frame_policy = canonical_digest({"schema": POLICY_REF, "max_slots": 4,
        "history_byte_safety_cap": 262144, "max_age_seconds": 72 * 3600,
        "installation": installation, "installed_full_wire_policy": None})
    raw = build_natural_frame_v4(window=window, plan=plan, question=question, installation=installation,
        frozen_at_utc=window.trusted_utc, expires_at_utc=window.trusted_utc + 30, policy_digest=frame_policy)
    public = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    policy = InstalledD13WirePolicyV1(installation, public, "test-policy", 1, "c" * 64,
        "d" * 64, "e" * 64, 1024, 0, 1, 1, 1, 0, max_slots=4)
    # Independent Authority composition uses its actual model ledger and
    # configured workflow. This is a D13 source gate, not an egress approval.
    import sqlite3
    from sylanne3.authority_service.d13_natural_frame_verifier_v1 import build_authority_d13_natural_frame_verifier_v1
    from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
    from sylanne3.host.authority_profile import AdminInstallationBundle
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION
    from sylanne3.runtime.d13_technical_policy import AdminD13PrecompressionPolicyV1
    from test_post_c02_reply_model_job_v1 import _reply_workflows
    workflows = _reply_workflows()
    workflows = replace(workflows, natural_generation=replace(workflows.reply,
        work_kind="natural_generation", template_version=TEMPLATE_VERSION, max_output_tokens=32,
        audiences=(window.conversation_ref,), quote_ceiling={"output_tokens": 32}))
    d13 = AdminD13PrecompressionPolicyV1(namespace, installed_policy.installation_id,
        installed_policy.root_grant.grant_id, installed_policy.root_grant.version,
        installed_policy.root_lease.lease_id, 4096, {"d13_compute_units": 1}, 300, 4, "d13:cpu")
    bundle = AdminInstallationBundle(object(), installed_policy, b"fixture", b"fixture",
        model_workflows=workflows, d13_precompression=d13)
    authority_db = sqlite3.connect(tmp_path / "independent-authority.sqlite", isolation_level=None)
    authority_db.execute("PRAGMA synchronous=FULL")
    authority_store = AuthorityV2ModelEgressStore(authority_db, create=True)
    verifier = build_authority_d13_natural_frame_verifier_v1(bundle=bundle,
        d11_issuer=graph._GraphCoordinator__d11_issuer, authority_store=authority_store)
    with pytest.raises(ValueError):
        build_authority_d13_natural_frame_verifier_v1(bundle=bundle,
            d11_issuer=graph._GraphCoordinator__d11_issuer, authority_store=object())
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            assert _verify_current_window(db, policy, raw, window, window.trusted_utc) == window
            checked = verifier.current_v4(db, frozen=raw, parent_original_id="test-current-source", now_utc=window.trusted_utc)
            assert checked is not None and checked.wire_digest == raw.model_request_digest
            assert checked.budget_state == "unverified"
            forged = replace(window, turns=(replace(window.turns[0], text="caller forged text"),))
            with pytest.raises(ValueError, match="independent source"):
                _verify_current_window(db, policy, raw, forged, window.trusted_utc)
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (window.turns[0].access_ref.ref,))
            with pytest.raises(Exception):
                _verify_current_window(db, policy, raw, window, window.trusted_utc)
            assert verifier.current_v4(db, frozen=raw, parent_original_id="test-current-source", now_utc=window.trusted_utc) is None
        finally:
            db.execute("ROLLBACK")
    authority_db.close()
