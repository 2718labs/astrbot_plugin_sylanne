"""D11 root evidence remains a scoped candidate with stable legacy digests."""

from dataclasses import fields, replace

import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime.d04_root_adoption_contract_v2 import (
    ROOT_ADOPTION_PHASE_V2, RootAdoptionEvidenceV2, RootAdoptionWriteV2,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DomainBundle, NamespaceId,
    OperationIdentity, QueryEpoch, SourceQualification, VersionGuard,
    VersionedRef, canonical_digest,
)


SHA = "a" * 64
NS = NamespaceId("bot", "persona")
OWNER = Owner("persona", "bot", "persona")


def _envelope() -> CommandEnvelope:
    return CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity", None, "attempt", ROOT_ADOPTION_PHASE_V2,
                          "root-op", canonical_digest({"input_refs": ["draft"]})),
        AuthorityContext("owner:one", "d11", "cap", NS, ("persona",),
                         "author_root", ("owner:one",), "policy", 1),
        VersionGuard(
            (GraphVersion(AtomKey(OWNER, "d01.identity.v1", "head"), 1),),
            (QueryEpoch(NS, "draft", 1),), 0, 0, "catalogue", "scheme",
            "operator", "policy", (), (), (),
        ),
        SourceQualification((), "authored", None, 1.0, "authored_content",
                            "ineligible", None, "not_applicable"),
        ("draft",), "budget", 2.0, 2.0, "interval", (),
    )


def _writes(namespace: NamespaceId = NS) -> tuple[RootAdoptionWriteV2, ...]:
    owner = Owner("persona", namespace.bot_id, namespace.persona_id)
    entries = []
    for name, kind in (("a", "d04.feeling_state.v1"),
                       ("b", "d04.feeling_state.v1"),
                       ("c", "d04.mood_field.v1")):
        entries.append(RootAdoptionWriteV2(
            AtomKey(owner, "d04.numeric_checkpoint.v1", name).token, SHA,
            AtomKey(owner, kind, name).token, SHA,
        ))
    return tuple(sorted(entries, key=lambda entry: entry.checkpoint_ref))


def _evidence(envelope: CommandEnvelope | None = None) -> RootAdoptionEvidenceV2:
    envelope = envelope or _envelope()
    writes = _writes()
    return RootAdoptionEvidenceV2(
        namespace=NS,
        operation_id="root-op",
        owner_actor="owner:one",
        owner_session_ref="session:one",
        owner_session_binding_digest=SHA,
        parent_budget_lease_ref="budget",
        parent_budget_original_digest=SHA,
        d01_head=VersionedRef("d01:head", 1),
        draft_head=VersionedRef("draft:head", 1),
        draft_digest=SHA,
        root_input_digest=SHA,
        candidate_digest=SHA,
        preset_digest=SHA,
        asset_digest=SHA,
        native_manifest_sha256=SHA,
        native_sha256=SHA,
        initial_transcript_digest=SHA,
        output_projection_digest=SHA,
        graph_read_set_digest=canonical_digest(envelope.version_guard.read_versions),
        writes=writes,
        output_write_set_digest=canonical_digest(writes),
        bundle_digest=SHA,
    )


def _bundle(envelope: CommandEnvelope | None = None,
            evidence: RootAdoptionEvidenceV2 | None = None) -> DomainBundle:
    return DomainBundle(envelope or _envelope(), (), (), (), (), (), (), (), (),
                        root_adoption=evidence)


def test_root_bundle_digest_binds_evidence_without_back_reference_loop() -> None:
    envelope = _envelope()
    provisional = _evidence(envelope)
    base = _bundle(envelope)
    digest = base.root_digest_with(provisional)
    evidence = replace(provisional, bundle_digest=digest)
    bundle = _bundle(envelope, evidence)
    assert bundle.digest == digest
    assert base.root_digest_with(replace(provisional, bundle_digest="b" * 64)) == digest
    assert base.root_digest_with(replace(provisional, initial_transcript_digest="b" * 64)) != digest
    assert base.root_digest_with(replace(provisional, output_projection_digest="b" * 64)) != digest
    for field_name in ("owner_session_binding_digest", "parent_budget_original_digest",
                       "draft_digest", "root_input_digest"):
        assert base.root_digest_with(replace(provisional, **{field_name: "b" * 64})) != digest
    assert base.root_digest_with(replace(provisional, writes=tuple(
        replace(item, state_value_digest="b" * 64) if index == 0 else item
        for index, item in enumerate(provisional.writes)
    ), output_write_set_digest=canonical_digest(tuple(
        replace(item, state_value_digest="b" * 64) if index == 0 else item
        for index, item in enumerate(provisional.writes)
    )))) != digest
    with pytest.raises(ValueError, match="bundle digest differs"):
        _bundle(envelope, provisional)


def test_root_evidence_rejects_wrong_scope_phase_and_incomplete_write_set() -> None:
    envelope = _envelope()
    evidence = _evidence(envelope)
    with pytest.raises(ValueError, match="phase"):
        replace(evidence, phase="prepare")
    with pytest.raises(ValueError, match="write set digest"):
        replace(evidence, output_write_set_digest="b" * 64)
    with pytest.raises(ValueError, match="Feeling and Mood"):
        replace(evidence, writes=evidence.writes[:2],
                output_write_set_digest=canonical_digest(evidence.writes[:2]))
    with pytest.raises(ValueError, match="cross namespace"):
        foreign = _writes(NamespaceId("other", "persona"))
        replace(evidence, writes=foreign, output_write_set_digest=canonical_digest(foreign))
    with pytest.raises(ValueError, match="scope and operation"):
        _bundle(envelope, replace(evidence, operation_id="other"))
    with pytest.raises(ValueError, match="scope and operation"):
        _bundle(envelope, replace(evidence, parent_budget_lease_ref="other-budget"))
    with pytest.raises(ValueError, match="read set differs"):
        _bundle(envelope, replace(evidence, graph_read_set_digest="b" * 64))
    with pytest.raises(TypeError, match="typed root evidence"):
        _bundle(envelope, object())


def test_root_field_does_not_change_legacy_bundle_digest() -> None:
    base = _bundle()
    old_wire = {
        "$type": f"{type(base).__module__}.{type(base).__qualname__}",
        **{field.name: getattr(base, field.name) for field in fields(base)
           if field.name not in {"product_advance", "root_adoption"}},
    }
    assert base.digest == canonical_digest(old_wire)
