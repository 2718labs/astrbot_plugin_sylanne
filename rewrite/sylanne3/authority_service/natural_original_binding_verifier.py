"""Read a natural model call's sealed original identity without authorizing egress."""

from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
import sqlite3

from ..host.authority_profile import AdminModelWorkflowV2
from ..model_broker.broker import ModelCallRequest
from ..model_broker.natural_reply import (
    TEMPLATE_DIGEST as GENERATION_TEMPLATE_DIGEST,
)
from ..model_broker.natural_review import REVIEW_TEMPLATE_DIGEST
from ..runtime.natural_reply_job_v2 import (
    NaturalReplyJobHold, read_original_call_binding,
    read_original_preparation,
)
from ..runtime.natural_original_v3 import natural_generation_template_digest
from ..runtime_contracts import (
    NATURAL_REPLY_GENERATION_WORKFLOW_V2,
    NATURAL_REPLY_REVIEW_WORKFLOW_V1,
    NamespaceId, NaturalReplyGenerationOriginalSealV2,
    NaturalReplyReviewOriginalSealV2,
)


@dataclass(frozen=True, slots=True)
class NaturalOriginalCallIdentityReadV2:
    """An acquired typed call exists; current graph and paid status remain HOLD."""

    stage: str
    seal: NaturalReplyGenerationOriginalSealV2 | NaturalReplyReviewOriginalSealV2
    request: ModelCallRequest
    typed_request_digest: str
    worker_fence: int
    status: str = "original_call_binding_only_hold"


class PinnedNaturalOriginalCallIdentityVerifierV2:
    """Read W07's original row from an administrator-pinned graph database.

    The workflow must come from the installed administrator profile. A caller
    cannot pass or replace the provider identity used by this verifier.
    """

    def __init__(
        self, graph_db_path: str | Path, *, installation_id: str,
        generation: AdminModelWorkflowV2 | None,
        review: AdminModelWorkflowV2 | None,
    ) -> None:
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("pinned graph database file required")
        if not installation_id:
            raise ValueError("installed identity required")
        self._path = path.resolve(strict=True)
        self._installation_id = installation_id
        self._workflows = {"generation": generation, "review": review}

    def read(
        self, namespace: NamespaceId, parent_original_id: str, stage: str,
    ) -> NaturalOriginalCallIdentityReadV2 | None:
        if (type(namespace) is not NamespaceId or not parent_original_id
                or stage not in ("generation", "review")):
            return None
        workflow = self._workflows[stage]
        if type(workflow) is not AdminModelWorkflowV2:
            return None
        expected = (
            ("natural_generation", NATURAL_REPLY_GENERATION_WORKFLOW_V2,
             GENERATION_TEMPLATE_DIGEST) if stage == "generation" else
            ("natural_review", NATURAL_REPLY_REVIEW_WORKFLOW_V1,
             REVIEW_TEMPLATE_DIGEST)
        )
        if stage == "generation":
            from ..model_broker.natural_reply_history_v3 import TEMPLATE_VERSION as V3_TEMPLATE_VERSION
            from ..model_broker.natural_reply_history_v4 import TEMPLATE_VERSION as V4_TEMPLATE_VERSION
            allowed = (expected[:2], ("natural_generation", V3_TEMPLATE_VERSION), ("natural_generation", V4_TEMPLATE_VERSION))
        else:
            allowed = (expected[:2],)
        if (workflow.work_kind, workflow.template_version) not in allowed:
            return None
        try:
            with closing(sqlite3.connect(
                    self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    saved = read_original_preparation(
                        db, namespace, parent_original_id, stage)
                    if saved is None or saved.state not in ("acquired", "terminal"):
                        return None
                    binding = read_original_call_binding(db, saved)
                    if binding is None:
                        return None
                    seal, frozen, request = (
                        saved.seal, saved.frozen, binding.request)
                    if stage == "generation":
                        expected = ("natural_generation", seal.template_version,
                                    natural_generation_template_digest(frozen))
                        if workflow.template_version != seal.template_version:
                            return None
                    installed = frozen.installation
                    if (seal.installation_id != self._installation_id
                            or installed.installation_id != self._installation_id
                            or seal.provider_config_digest !=
                               workflow.provider_config_digest
                            or (installed.provider_id, installed.model_id,
                                installed.provider_config_digest,
                                installed.max_output_tokens) !=
                               (workflow.provider_id, workflow.model_id,
                                workflow.provider_config_digest,
                                workflow.max_output_tokens)
                            or (request.provider_id, request.model_id,
                                request.privacy_tier,
                                request.prompt_template_digest,
                                request.timeout_seconds,
                                request.max_output_tokens) !=
                               (workflow.provider_id, workflow.model_id,
                                workflow.privacy_tier, expected[2],
                                workflow.timeout_seconds,
                                workflow.max_output_tokens)
                            or request.required_capabilities !=
                               frozenset(workflow.required_capabilities)
                            or request.identity.phase != "natural_" + stage
                            or request.envelope.authority.namespace != namespace
                            or request.envelope.authority.purpose != workflow.purpose
                            or not request.envelope.authority.audience
                            or not set(request.envelope.authority.audience) <=
                               set(workflow.audiences)
                            or request.envelope.authority.provider_policy_ref !=
                               workflow.provider_config_ref
                            or request.envelope.parent_budget_lease_ref !=
                               seal.parent_budget_lease_id
                            or request.digest != binding.typed_request_digest
                            or request.call_id != seal.call_id
                            or request.identity.operation_id !=
                               seal.acquire_operation_id
                            or binding.worker_fence != saved.worker_fence):
                        return None
                    return NaturalOriginalCallIdentityReadV2(
                        stage, seal, request, binding.typed_request_digest,
                        binding.worker_fence)
                finally:
                    db.execute("ROLLBACK")
        except (NaturalReplyJobHold, sqlite3.Error, KeyError, IndexError,
                TypeError, ValueError, AttributeError):
            return None


__all__ = [
    "NaturalOriginalCallIdentityReadV2",
    "PinnedNaturalOriginalCallIdentityVerifierV2",
]
