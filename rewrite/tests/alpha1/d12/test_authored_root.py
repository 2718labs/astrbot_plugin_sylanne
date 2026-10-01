"""D12's current draft selects D04 root inputs without granting adoption."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.root import (
    AuthoredRootPreset, RootAssetBindings, RootBlockTemplate,
)
from sylanne3.domains.d12 import (
    CharacterDraft, D12CurrentCreatorDraftV1, D12SchemeHold,
    active_scheme_head_key, character_draft_key, issue_authored_root_intent_v2,
)
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId


def _current():
    namespace = NamespaceId("bot", "persona")
    assets = RootAssetBindings(
        "scheme:1", "operator:1", "parameter:1", "coupling:1", "readout:1",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
    )
    axes = tuple(f"axis:{n:02d}" for n in range(24))
    preset = AuthoredRootPreset(
        "preset:shared", "v1", assets, axes,
        (RootBlockTemplate("feeling", "feeling", "author_supplied_box"),
         RootBlockTemplate("mood", "mood", "author_supplied_box")),
    )
    blocks = []
    for kind in ("feeling", "mood"):
        blocks.append({
            "identity": {
                "block_id": kind, "template_id": kind, "kind": kind,
                "object_ref": "person:owner" if kind == "feeling" else None,
                "meaning_ref": "meaning:care" if kind == "feeling" else None,
                "authored_source_id": f"author:{kind}",
            },
            "axes": list(axes), "latent_state": [2.0] * 24,
            "ordered_box": [[1.9, 2.1] for _ in axes],
            "initial_error_ref": f"bounds:{kind}",
        })
    selection = {
        "candidate_id": "candidate:root", "cursor": 0.0,
        "preset_digest": preset.digest, "asset_digest": assets.digest,
        "blocks": blocks,
    }
    draft = CharacterDraft("persona", 2, {"d04.authored_root": selection},
                           {"d04.authored_root": "owner_authored"})
    frame = D12CurrentCreatorDraftV1(
        namespace, character_draft_key(namespace).token, 2, draft,
        active_scheme_head_key(namespace).token, 1, 8, 2, 3, True,
    )
    authority = AuthorityContext(
        "owner:one", "d12", "cap:creator", namespace, ("persona",),
        "authoring", ("owner",), "policy", 1,
    )
    return frame, authority, preset


def _issue(frame, authority, preset):
    return issue_authored_root_intent_v2(
        frame, authority, operation_id="root:one", owner_actor_id="owner:one",
        owner_session_id="session:one", installed_preset=preset,
    )


def test_current_draft_issues_bound_root_input_candidate():
    frame, authority, preset = _current()
    intent = _issue(frame, authority, preset)
    assert intent.status == "hold_for_d11_root_adoption"
    assert intent.namespace == frame.namespace
    assert intent.owner_actor_id == intent.root_input.author_id == authority.actor
    assert intent.owner_session_id == "session:one"
    assert intent.draft_revision == frame.draft_revision
    assert intent.active_head_revision == frame.active_head_revision
    assert intent.root_input.draft_id.startswith(f"{frame.draft_ref}@2:")
    assert intent.preset_digest == preset.digest
    assert len(intent.candidate_digest) == len(intent.input_digest) == 64
    assert len(intent.root_input.blocks) == 2


def test_root_choice_requires_current_authorized_exact_draft_and_owner():
    frame, authority, preset = _current()
    for bad in (
        replace(frame, creator_authorized=False),
        replace(frame, draft_revision=3),
        replace(frame, active_head_ref=frame.draft_ref),
        replace(frame, draft=CharacterDraft("persona", 2, {}, {})),
    ):
        with pytest.raises(D12SchemeHold):
            _issue(bad, authority, preset)
    with pytest.raises(D12SchemeHold, match="Owner actor"):
        issue_authored_root_intent_v2(
            frame, authority, operation_id="root:one", owner_actor_id="browser",
            owner_session_id="session:one", installed_preset=preset,
        )


def test_root_choice_rejects_browser_identity_and_installed_preset_drift():
    frame, authority, preset = _current()
    selected = dict(frame.draft.fields["d04.authored_root"])
    selected["author_id"] = "browser"
    draft = CharacterDraft("persona", 2, {"d04.authored_root": selected},
                           frame.draft.field_sources)
    with pytest.raises(D12SchemeHold):
        _issue(replace(frame, draft=draft), authority, preset)
    changed = replace(preset, assets=replace(preset.assets, scheme_sha256="f" * 64))
    with pytest.raises(D12SchemeHold, match="installed preset"):
        _issue(frame, authority, changed)


def test_changed_draft_or_head_changes_intent_binding():
    frame, authority, preset = _current()
    original = _issue(frame, authority, preset)
    updated = dict(frame.draft.fields["d04.authored_root"])
    updated["candidate_id"] = "candidate:next"
    draft = CharacterDraft("persona", 3, {"d04.authored_root": updated},
                           frame.draft.field_sources)
    revised = _issue(replace(frame, draft=draft, draft_revision=3,
                             active_head_revision=2), authority, preset)
    assert revised.input_digest != original.input_digest
    assert revised.candidate_digest != original.candidate_digest
    assert revised.active_head_revision == 2


def test_other_creator_fields_remain_in_bound_draft_digest():
    frame, authority, preset = _current()
    original = _issue(frame, authority, preset)
    draft = CharacterDraft(
        "persona", 2,
        {**frame.draft.fields, "d01.name": "Sylanne"},
        {**frame.draft.field_sources, "d01.name": "owner_authored"},
    )
    combined = _issue(replace(frame, draft=draft), authority, preset)
    assert combined.draft_digest != original.draft_digest
    assert combined.input_digest != original.input_digest
    assert combined.preset_digest == original.preset_digest
