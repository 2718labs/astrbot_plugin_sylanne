"""V3 authored root evidence is disjoint from held event-derived V2."""

from dataclasses import fields, replace

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d04_root_adoption_contract_v2 import (
    RootAdoptionEvidenceV2, RootAdoptionWriteV2,
)
from sylanne3.runtime.d04_root_adoption_contract_v3 import (
    ROOT_ADOPTION_PHASE_V3, ROOT_ADOPTION_SCHEMA_V3,
    RootAdoptionEvidenceV3, RootAdoptionWriteV3,
    root_adoption_evidence_digest_v3, root_adoption_from_wire_v3,
    root_adoption_to_wire_v3,
)
from sylanne3.runtime_contracts import NamespaceId, VersionedRef, canonical_digest


H = "a" * 64


def key(type_name, block):
    return AtomKey(Owner("persona", "bot", "persona"), type_name, block).token


def writes(version):
    checkpoint = "d04.numeric_checkpoint.v1" if version == 1 else "d04.numeric_checkpoint.v2"
    feeling = "d04.feeling_state.v1" if version == 1 else "d04.authored_feeling_state.v1"
    mood = "d04.mood_field.v1" if version == 1 else "d04.authored_mood_state.v1"
    kind = RootAdoptionWriteV2 if version == 1 else RootAdoptionWriteV3
    result = []
    for block, state_type in (("f1", feeling), ("f2", feeling), ("m", mood)):
        args = (key(checkpoint, block), H, key(state_type, block), H)
        if version == 3:
            args = (args[0], 1, args[1], args[2], 1, args[3])
        result.append(kind(*args))
    return tuple(sorted(result, key=lambda item: item.checkpoint_ref))


def old_evidence():
    pairs = writes(1)
    return RootAdoptionEvidenceV2(
        NamespaceId("bot", "persona"), "root-op", "owner", "session", H,
        "lease", H, VersionedRef(key("d01.role_head.v1", "current"), 1),
        VersionedRef(key("d12.character_draft.v1", "current"), 2),
        H, H, H, H, H, H, H, H, H, H, pairs, canonical_digest(pairs), H)


def authored_evidence():
    pairs = writes(3)
    values = dict(
        namespace=NamespaceId("bot", "persona"), operation_id="root-op",
        owner_actor="owner", owner_session_ref="session",
        owner_session_binding_digest=H, parent_budget_lease_ref="lease",
        parent_budget_original_digest=H, d11_freeze_original_digest=H,
        d11_grant_digest=H, d11_grant_signature_digest=H,
        d11_reserve_receipt_digest=H,
        active_scheme_head=VersionedRef(key("d12.active_scheme_head.v1", "current"), 1),
        draft_head=VersionedRef(key("d12.character_draft.v1", "current"), 2),
        draft_digest=H, root_input_digest=H, candidate_digest=H,
        preset_digest=H, asset_digest=H, native_manifest_sha256=H,
        native_sha256=H, abi2_initial_box_digest=H, abi2_readout_digest=H,
        output_projection_digest=H, graph_read_set_digest=H, writes=pairs,
        output_write_set_digest=H,
        write_commitment_digest=canonical_digest(pairs), bundle_digest=H,
        phase=ROOT_ADOPTION_PHASE_V3, schema=ROOT_ADOPTION_SCHEMA_V3,
    )
    return RootAdoptionEvidenceV3(
        **values, evidence_digest=root_adoption_evidence_digest_v3(values))


def test_v2_digest_is_stable_and_v3_round_trips_only_its_own_wire():
    old = old_evidence()
    assert canonical_digest(old) == "e2814cac498bf7f2407a9936cc92dd9e23271a573d1d75e2d8d4a4fb7d066173"
    new = authored_evidence()
    assert new.active_scheme_head.ref == key("d12.active_scheme_head.v1", "current")
    assert root_adoption_from_wire_v3(root_adoption_to_wire_v3(new)) == new
    with pytest.raises(ValueError, match="V3 root wire fields differ"):
        root_adoption_from_wire_v3({field.name: getattr(old, field.name)
                                    for field in fields(old)})
    with pytest.raises(ValueError, match="phase differs"):
        replace(new, phase=old.phase)
    with pytest.raises(ValueError, match="active scheme"):
        replace(new, active_scheme_head=VersionedRef(key("d01.role_head.v1", "current"), 1))


def test_v3_rejects_event_derived_and_incomplete_authored_writes():
    with pytest.raises(ValueError, match="paired rev1 authored state"):
        RootAdoptionWriteV3(
            key("d04.numeric_checkpoint.v2", "f1"), 1, H,
            key("d04.feeling_state.v1", "f1"), 1, H)
    with pytest.raises(ValueError, match="paired rev1 authored state"):
        RootAdoptionWriteV3(
            key("d04.numeric_checkpoint.v1", "f1"), 1, H,
            key("d04.authored_feeling_state.v1", "f1"), 1, H)
    altered = writes(3)
    altered = (*altered[:-1], replace(
        altered[-1], state_ref=key("d04.authored_feeling_state.v1", "m")))
    with pytest.raises(ValueError, match="two authored Feelings"):
        replace(authored_evidence(), writes=altered)
