"""Pure D12 author selection for the D04 revision-zero root.

W01 must supply a current fenced draft and a verified Owner session.  This
intent is a bound input for D11; it is not a graph write or adoption permit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ...runtime_contracts import AuthorityContext, NamespaceId, canonical_digest
from ..d04.root import (
    AuthoredRootBlockInput, AuthoredRootInput, AuthoredRootPreset,
    RootBlockIdentity, compile_authored_root_candidate,
)
from .scheme_command import D12CurrentCreatorDraftV1, D12SchemeCommandIssuer, D12SchemeHold


ROOT_FIELD = "d04.authored_root"


@dataclass(frozen=True, slots=True)
class D12AuthoredRootIntentV2:
    operation_id: str
    namespace: NamespaceId
    owner_actor_id: str
    owner_session_id: str
    draft_ref: str
    draft_revision: int
    draft_digest: str
    active_head_ref: str
    active_head_revision: int
    graph_revision: int
    access_epoch: int
    delete_epoch: int
    field_source: str
    preset_digest: str
    asset_digest: str
    input_digest: str
    candidate_digest: str
    root_input: AuthoredRootInput
    status: str = "hold_for_d11_root_adoption"


def _exact_object(value: object, names: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != names:
        raise D12SchemeHold(f"{label} fields differ from authored root selection")
    return value


def _exact_array(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise D12SchemeHold(f"{label} must be an array")
    return value


def issue_authored_root_intent_v2(
    frame: D12CurrentCreatorDraftV1,
    authority: AuthorityContext,
    *,
    operation_id: str,
    owner_actor_id: str,
    owner_session_id: str,
    installed_preset: AuthoredRootPreset,
) -> D12AuthoredRootIntentV2:
    """Extract an exact D04 choice from W01's authenticated current draft.

    W01 obtains the frame under its creator read fence, verifies the signed
    Owner session and installed preset independently, and passes only those
    trusted facts here. D11 must persist and sign the frozen adoption evidence.
    """
    D12SchemeCommandIssuer._authority(authority)
    draft_digest = D12SchemeCommandIssuer._current(frame, authority)
    if (type(operation_id) is not str or not operation_id.strip()
            or type(owner_actor_id) is not str or not owner_actor_id.strip()
            or type(owner_session_id) is not str or not owner_session_id.strip()
            or authority.actor != owner_actor_id):
        raise D12SchemeHold("verified Owner actor or session is unavailable")
    if type(installed_preset) is not AuthoredRootPreset:
        raise D12SchemeHold("installed D04 root preset is unavailable")
    if ROOT_FIELD not in frame.draft.fields or ROOT_FIELD not in frame.draft.field_sources:
        raise D12SchemeHold("current draft has no D04 root choice")
    source = frame.draft.field_sources[ROOT_FIELD]
    if type(source) is not str or not source.strip():
        raise D12SchemeHold("D04 root choice has no author source")
    value = _exact_object(frame.draft.fields[ROOT_FIELD], {
        "candidate_id", "cursor", "preset_digest", "asset_digest", "blocks",
    }, ROOT_FIELD)
    if (value["preset_digest"] != installed_preset.digest
            or value["asset_digest"] != installed_preset.assets.digest):
        raise D12SchemeHold("D04 root choice differs from installed preset")
    try:
        blocks = []
        for item in _exact_array(value["blocks"], "blocks"):
            block = _exact_object(item, {
                "identity", "axes", "latent_state", "ordered_box", "initial_error_ref",
            }, "root block")
            identity = RootBlockIdentity(**_exact_object(block["identity"], {
                "block_id", "template_id", "kind", "object_ref", "meaning_ref",
                "authored_source_id",
            }, "block identity"))
            blocks.append(AuthoredRootBlockInput(
                identity=identity,
                axes=tuple(_exact_array(block["axes"], "axes")),
                latent_state=tuple(_exact_array(block["latent_state"], "latent_state")),
                ordered_box=tuple(tuple(_exact_array(pair, "ordered_box interval"))
                                  for pair in _exact_array(block["ordered_box"], "ordered_box")),
                initial_error_ref=block["initial_error_ref"],
            ))
        root_input = AuthoredRootInput(
            candidate_id=value["candidate_id"],
            namespace=frame.namespace.as_tuple,
            author_id=owner_actor_id,
            draft_id=f"{frame.draft_ref}@{frame.draft_revision}:{draft_digest}",
            cursor=value["cursor"],
            preset_digest=installed_preset.digest,
            asset_digest=installed_preset.assets.digest,
            blocks=tuple(blocks),
        )
        candidate = compile_authored_root_candidate(installed_preset, root_input)
    except (TypeError, ValueError) as exc:
        raise D12SchemeHold("D04 root choice is invalid") from exc
    return D12AuthoredRootIntentV2(
        operation_id=operation_id, namespace=frame.namespace,
        owner_actor_id=owner_actor_id, owner_session_id=owner_session_id,
        draft_ref=frame.draft_ref, draft_revision=frame.draft_revision,
        draft_digest=draft_digest, active_head_ref=frame.active_head_ref,
        active_head_revision=frame.active_head_revision,
        graph_revision=frame.graph_revision, access_epoch=frame.access_epoch,
        delete_epoch=frame.delete_epoch, field_source=source,
        preset_digest=installed_preset.digest,
        asset_digest=installed_preset.assets.digest,
        input_digest=canonical_digest(root_input), candidate_digest=candidate.digest,
        root_input=root_input,
    )
