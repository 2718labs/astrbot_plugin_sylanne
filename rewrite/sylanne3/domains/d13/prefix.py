"""Identity of the unchanged D13 text segment, not a provider cache receipt."""

from __future__ import annotations

from ...runtime_contracts import (
    ConversationWindowProjectionV1, ShortContextRequestV1, canonical_digest,
)


def stable_segment_digest(
    window: ConversationWindowProjectionV1,
    request: ShortContextRequestV1,
    stable_text: str,
) -> str:
    """Bind only actual reusable D13 text plus its rendering profile.

    Raw mode has no stable history segment, so ``stable_text`` is empty.
    Active mode supplies the rendered block timeline before its dynamic raw
    tail and detail slots. This digest neither describes the full request nor
    establishes a provider cache hit.
    """
    return canonical_digest({
        "schema": "d13.stable_segment.v1",
        "namespace": window.namespace,
        "owner": window.owner_ref,
        "conversation": window.conversation_ref,
        "scene": window.scene_ref,
        "audience": window.audience_ref,
        "provider": request.provider_id,
        "model": request.model_id,
        "template": request.template_version,
        "tools": request.tool_profile_version,
        "text": stable_text,
    })
