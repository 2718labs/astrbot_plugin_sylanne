"""Identity and recovery facts cannot masquerade as namespace authorization."""

from dataclasses import replace

import pytest

from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    AUTHORITY_BOOTSTRAP_SCHEMA_V2,
    InstallationGrantV2,
    NamespaceBootstrapV2,
    NamespaceId,
    NamespaceRuntimeState,
    SnapshotRequirementsV2,
    canonical_serialize,
)


def grant() -> InstallationGrantV2:
    return InstallationGrantV2(
        authority_id="authority-A",
        subject="mtls:subject-A",
        administrator_holder="holder-A",
        installation_id="installation-A",
        manifest_digest="a" * 64,
        publisher_policy_ref="publisher-policy-v1",
        service_capability_version="authority-service-v2",
        channel_binding_sha256="b" * 64,
    )


def anchor() -> RestoreAnchor:
    return RestoreAnchor(
        authority_id="authority-A",
        namespace="namespace-A",
        activation_generation=3,
        deletion_journal_id="deletion-A",
        deletion_seq=0,
        deletion_digest="genesis",
        execution_journal_id="execution-A",
        execution_seq=2,
        execution_digest="sha256:" + "c" * 64,
        revocation_epoch=1,
        proof="opaque-proof",
    )


def bootstrap() -> NamespaceBootstrapV2:
    return NamespaceBootstrapV2(
        authority_id="authority-A",
        namespace=NamespaceId("bot-A", "persona-A"),
        authority_namespace="namespace-A",
        holder="holder-A",
        generation=3,
        phase="active",
        state=NamespaceRuntimeState.ACTIVE,
        anchor=anchor(),
        blocking_reasons=(),
    )


def test_installation_grant_is_channel_bound_fact_without_global_generation():
    item = grant()
    assert item.schema == AUTHORITY_BOOTSTRAP_SCHEMA_V2
    assert "activation_generation" not in item.__dataclass_fields__
    assert "generation" not in item.__dataclass_fields__
    assert "channel_binding_sha256" in canonical_serialize(item)
    with pytest.raises(ValueError, match="channel_binding_sha256"):
        replace(item, channel_binding_sha256="A" * 64)
    with pytest.raises(ValueError, match="manifest_digest"):
        replace(item, manifest_digest="a" * 63)
    with pytest.raises(ValueError, match="schema"):
        replace(item, schema="sylanne3.authority.v1")


def test_active_bootstrap_requires_exact_anchor_and_no_blocker():
    item = bootstrap()
    assert item.anchor == anchor()
    for changed_anchor in (
        replace(anchor(), authority_id="authority-B"),
        replace(anchor(), namespace="namespace-B"),
        replace(anchor(), activation_generation=4),
    ):
        with pytest.raises(ValueError, match="anchor authority, namespace or generation mismatch"):
            replace(item, anchor=changed_anchor)
    for change in (
        {"anchor": None},
        {"holder": None},
        {"phase": "recovering"},
        {"blocking_reasons": ("deletion pending",)},
    ):
        with pytest.raises(ValueError, match="active namespace requires"):
            replace(item, **change)
    with pytest.raises(ValueError, match="anchor authority, namespace or generation mismatch"):
        replace(item, generation=0)


def test_unbound_and_blocked_states_are_explicit_and_cannot_claim_active():
    unbound = replace(
        bootstrap(), holder=None, generation=0, phase="unbound",
        state=NamespaceRuntimeState.UNBOUND, anchor=None,
    )
    assert unbound.anchor is None
    with pytest.raises(ValueError, match="unbound namespace"):
        replace(unbound, holder="holder-A")
    recovering = replace(bootstrap(), state=NamespaceRuntimeState.RECOVERING,
                         blocking_reasons=("journal recovery pending",))
    assert recovering.blocking_reasons == ("journal recovery pending",)
    with pytest.raises(ValueError, match="blocking reasons"):
        replace(recovering, blocking_reasons=())
    with pytest.raises(TypeError, match="state"):
        replace(bootstrap(), state="active")


def test_anchor_requires_complete_coherent_heads():
    with pytest.raises(ValueError, match="invalid execution head"):
        replace(bootstrap(), anchor=replace(anchor(), execution_seq=0))
    with pytest.raises(ValueError, match="execution_digest"):
        replace(bootstrap(), anchor=replace(anchor(), execution_digest="sha256:" + "X" * 64))


def test_snapshot_requirements_v2_pin_full_heads_and_graph_incarnation():
    snapshot = SnapshotRequirementsV2(
        namespace=NamespaceId("bot-A", "persona-A"),
        authority_id="authority-A", authority_namespace="namespace-A",
        activation_generation=3, deletion_journal_id="deletion-A",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-A", execution_seq=2,
        execution_digest="sha256:" + "c" * 64,
        revocation_epoch=1, graph_incarnation="graph-incarnation-A",
    )
    assert snapshot.schema == AUTHORITY_BOOTSTRAP_SCHEMA_V2
    assert snapshot.execution_journal_id == "execution-A"
    assert snapshot.graph_incarnation == "graph-incarnation-A"
    for change in (
        {"deletion_digest": "sha256:" + "a" * 64},
        {"execution_seq": 0},
        {"execution_digest": "sha256:" + "C" * 64},
        {"execution_digest": "genesis"},
    ):
        with pytest.raises(ValueError):
            replace(snapshot, **change)
