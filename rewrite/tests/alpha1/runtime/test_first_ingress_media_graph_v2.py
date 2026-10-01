"""Captioned media joins the real first-ingress graph and byte transaction."""

import hashlib
import json
import time
from uuid import uuid4

import pytest

from sylanne3.domains.d06 import SourceAdmission
from sylanne3.domains.d06.attachment_contract_v2 import (
    SourceAdmissionV2, SourceAttachmentV2,
)
from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
from sylanne3.graph_coordinator import AuthorityContext, UnavailableGuard
from sylanne3.runtime.source_attachment_graph_v2 import (
    media_source_key, read_media_blobs,
)

from test_first_ingress_v2 import ingress_system
from test_first_ingress_v2 import _ingress_inputs
from test_scene_binding_v2 import _bind_scene, _scene_case, _session


def _staged(host, content=b"actual image bytes"):
    source = SourceAdmission(
        host.lineage.source_ref, host.text, host.sender_ref,
        host.lineage.source_kind, "reported",
        host.lineage.evidence_eligibility,
        host.lineage.internal_activity_actuality,
        host.occurred_at, 11.0, host.lineage.provenance_family,
        (host.conversation_ref,), ("context", "consolidation"),
    )
    return SourceAdmissionV2(source, (
        SourceAttachmentV2(0, "image", "image/png", content,
                           hashlib.sha256(content).hexdigest()),
    ))


def test_captioned_media_is_atomic_and_replay_binds_actual_bytes(ingress_system):
    store, graph, bootstrap, _, policy, clock, encoding, host = ingress_system
    staged = _staged(host)
    receipt = graph.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding,
        source_admission_v2=staged)
    assert receipt.status == "committed"
    key = media_source_key(host.namespace, host.lineage.source_ref)
    row = store._db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (key.token,),
    ).fetchone()
    assert (row[0], row[2]) == (1, 1)
    assert read_media_blobs(store._db, host.namespace,
                            host.lineage.source_ref, json.loads(row[1])) == (
                                staged.attachments[0].content,)
    assert graph.commit_first_ingress_v2(
        bootstrap, host, policy, clock, encoding,
        source_admission_v2=staged) == receipt
    with pytest.raises(UnavailableGuard, match="intent identity differs"):
        graph.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding,
            source_admission_v2=_staged(host, b"different image bytes"))


def test_failed_media_bundle_rolls_back_bytes_and_source(ingress_system):
    store, graph, bootstrap, _, policy, clock, encoding, host = ingress_system
    provider = graph._GraphCoordinator__providers["d06"][0]
    original = provider.validate
    provider.validate = lambda *_: (_ for _ in ()).throw(
        RuntimeError("graph validation failed"))
    try:
        with pytest.raises(RuntimeError, match="graph validation failed"):
            graph.commit_first_ingress_v2(
                bootstrap, host, policy, clock, encoding,
                source_admission_v2=_staged(host))
    finally:
        provider.validate = original
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_source_attachment_blobs_v2").fetchone() == (0,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='memory.source.v2'"
    ).fetchone() == (0,)


def test_current_scoped_media_read_denied_after_owner_access_revoke(tmp_path):
    case = _scene_case(
        tmp_path, enable_ingress=True,
        owner_capabilities=("workbench.create", "workbench.read",
                            "workbench.bind_scene", "workbench.correct"),
        owner_purposes=("workbench_user_action", "workbench_view", "audit"),
    )
    store, authority_db, _, graph, namespace, _, _, policy, bootstrap = case
    try:
        _bind_scene(case)
        host, clock, encoding = _ingress_inputs(namespace)
        graph.commit_first_ingress_v2(
            bootstrap, host, policy, clock, encoding,
            source_admission_v2=_staged(host))
        lease, ref = graph.grant(
            bootstrap, actor="administrator", issuer_domain="d06",
            namespace=namespace, domains=("d06",),
            activation_generation=1)
        reader = AuthorityContext(
            "administrator", "d06", ref, namespace, ("event",),
            "context", (host.conversation_ref,), policy.root_grant.policy_ref, 1)
        assert graph.read_current_source_media_v2(
            reader, lease, source_id=host.lineage.source_ref).contents == (
                b"actual image bytes",)
        token, request = _session(case)
        owner, owner_lease, _ = graph.grant_current_owner(
            bootstrap, actor="paired-owner", namespace=namespace,
            domains=("d06", "d11"), purpose="audit", audience="owner",
            activation_generation=1, owner_session_token=token,
            owner_session_request=request)
        graph.revoke_source_access_v1(
            owner, owner_lease,
            SourceAccessRevocationRequest(
                host.lineage.source_ref, "paired-owner", str(uuid4()),
                time.time()),
        )
        assert store._db.execute(
            "SELECT COUNT(*) FROM graph_source_attachment_blobs_v2"
        ).fetchone() == (0,)
        with pytest.raises(UnavailableGuard):
            graph.read_current_source_media_v2(
                reader, lease, source_id=host.lineage.source_ref)
    finally:
        store.close()
        authority_db.close()
