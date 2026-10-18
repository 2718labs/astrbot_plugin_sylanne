"""Non-authorizing comparison for provisional and final dispatch checks.

The installed final reader must issue evidence from the *sealed* graph rows in
the graph receipt hook. Equality here cannot authenticate a supplied reader or
turn a provisional check into an admission or send permit.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import Callable

from ..graph_types import GraphReceipt
from ..runtime_contracts import (
    CheckReceipt, FenceScope, QueryEpoch, VersionedRef, canonical_digest,
)
from .restore_anchor import RestoreAnchor


class DispatchCheckReissueHold(RuntimeError):
    """The final sealed graph did not reproduce its provisional check set."""


@dataclass(frozen=True, slots=True)
class NegativeQueryClosureV1:
    predicate_ref: str
    query: QueryEpoch
    scanned_versions: tuple[VersionedRef, ...]
    matching_count: int
    coverage: str

    def __post_init__(self) -> None:
        if (type(self.predicate_ref) is not str or not self.predicate_ref
                or type(self.query) is not QueryEpoch
                or type(self.matching_count) is not int
                or self.matching_count < 0 or self.coverage != "full"
                or any(type(item) is not VersionedRef
                       for item in self.scanned_versions)):
            raise ValueError("negative query requires a complete typed closure")
        object.__setattr__(self, "scanned_versions", tuple(self.scanned_versions))


@dataclass(frozen=True, slots=True)
class ProvisionalCheckCandidateV1:
    """Expected fields only; this object never grants a passing check."""

    event_session: str
    event_id: str
    graph_epoch: int
    authority_head: RestoreAnchor
    authority_snapshot_digest: str
    permit_token: str
    positive_reads: tuple[VersionedRef, ...]
    negative_queries: tuple[NegativeQueryClosureV1, ...]
    checks: tuple[CheckReceipt, ...]

    def __post_init__(self) -> None:
        if (any(type(value) is not str or not value for value in (
                self.event_session, self.event_id,
                self.authority_snapshot_digest, self.permit_token))
                or type(self.graph_epoch) is not int or self.graph_epoch < 1
                or type(self.authority_head) is not RestoreAnchor
                or not self.positive_reads or not self.negative_queries
                or not self.checks
                or any(type(item) is not VersionedRef
                       for item in self.positive_reads)
                or any(type(item) is not NegativeQueryClosureV1
                       for item in self.negative_queries)
                or any(type(item) is not CheckReceipt for item in self.checks)):
            raise ValueError("provisional check candidate lacks complete typed fields")
        object.__setattr__(self, "positive_reads", tuple(self.positive_reads))
        object.__setattr__(self, "negative_queries", tuple(self.negative_queries))
        object.__setattr__(self, "checks", tuple(self.checks))


@dataclass(frozen=True, slots=True)
class PostC02FinalReissueV2:
    """Coordinator-issued detail from actual sealed E+1 rows.

    Construction is not authority.  The receipt hook first passes this through
    ``reissue_and_require_identical_checks`` under its ordinary write fence;
    only the verified return may be offered to the installed admission issuer.
    """

    candidate: ProvisionalCheckCandidateV1
    route_binding: object
    social: object
    d08_scope: object
    grant: object
    action: object
    graph_receipt: GraphReceipt

    def __post_init__(self) -> None:
        from ..domains.d03.prebatch_social import PrebatchSocialCandidateV1
        from ..domains.d08 import CommunicationIntentGrant, DispatchCheckScopeV2
        from .post_c02_reply_action_v2 import PostC02ReplyActionCandidateV2
        from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2

        if (type(self.candidate) is not ProvisionalCheckCandidateV1
                or type(self.route_binding) is not CurrentReplyEntityRouteBindingV2
                or type(self.social) is not PrebatchSocialCandidateV1
                or type(self.d08_scope) is not DispatchCheckScopeV2
                or type(self.grant) is not CommunicationIntentGrant
                or type(self.action) is not PostC02ReplyActionCandidateV2
                or type(self.graph_receipt) is not GraphReceipt
                or self.graph_receipt.status != "committed"
                or self.graph_receipt.epoch.revision != self.candidate.graph_epoch
                or self.route_binding.query.revision != self.candidate.graph_epoch
                or self.social.status != "checks_candidate"
                or self.action.status != "candidate"
                or self.grant.route_binding_digest is None
                or len(self.candidate.checks) != 5
                or self.grant.route_binding_digest
                   != canonical_digest(self.route_binding)
                or self.action.intent.action_id != self.d08_scope.action_id
                or self.action.intent.target_ref
                   != self.route_binding.target_entity_ref
                or self.grant.target_ref != self.route_binding.target_entity_ref
                or self.grant.audiences
                   != (self.route_binding.conversation_ref,)
                or self.candidate.checks != (
                    self.social.role_receipt,
                    self.social.boundary_receipt,
                    self.candidate.checks[2],
                    self.d08_scope.receipt,
                    self.candidate.checks[4])):
            raise DispatchCheckReissueHold(
                "final post-C02 check detail is incomplete")


def reissue_and_require_identical_checks(
    db, provisional: ProvisionalCheckCandidateV1,
    final_receipt: GraphReceipt, scope: FenceScope, *, now_utc: float,
    installed_reissuer: Callable,
) -> PostC02FinalReissueV2 | None:
    """Run an installed reader in the final receipt hook and compare exactly.

    The GraphCoordinator must supply ``installed_reissuer`` from its own
    installation, never from a caller. It must re-enumerate positive and
    negative reads from the final SQL rows and return a typed candidate.
    This function grants no permission; the coordinator still validates the
    live Authority fence after the outer transaction commits.
    """
    if (not db.in_transaction or type(provisional) is not ProvisionalCheckCandidateV1
            or type(final_receipt) is not GraphReceipt
            or final_receipt.status != "committed"
            or type(scope) is not FenceScope or scope.operation != "write"
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or not callable(installed_reissuer)):
        raise DispatchCheckReissueHold("final check reissue context is unavailable")
    namespace = scope.namespace
    if (scope.pinned_anchor != provisional.authority_head
            or scope.permit.pinned_anchor != provisional.authority_head
            or scope.permit.token != provisional.permit_token
            or final_receipt.epoch.bot != namespace.bot_id
            or final_receipt.epoch.persona != namespace.persona_id
            or final_receipt.epoch.revision != provisional.graph_epoch
            or final_receipt.epoch.revision != scope.graph_epoch.revision + 1):
        raise DispatchCheckReissueHold("final Authority head or graph epoch differs")
    event = db.execute(
        "SELECT revisions,epoch_revision FROM graph_events WHERE bot=? "
        "AND persona=? AND session=? AND event_id=?",
        namespace.as_tuple + (
            provisional.event_session, provisional.event_id),
    ).fetchone()
    current_epoch = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    expected_revisions = [
        [item.key.token, item.revision] for item in final_receipt.revisions]
    if (event is None or json.loads(event[0]) != expected_revisions
            or event[1] != provisional.graph_epoch
            or current_epoch != (provisional.graph_epoch,)):
        raise DispatchCheckReissueHold("final graph event or epoch is absent")
    detail = installed_reissuer(db, final_receipt, scope, now_utc)
    from .artifact_receipt_graph_v1 import is_actual_artifact_receipt_final_reissue_v1
    artifact=is_actual_artifact_receipt_final_reissue_v1(detail,db,now_utc=now_utc,scope=scope)
    final = (detail.candidate if (type(detail) is PostC02FinalReissueV2 or artifact)
             else detail)
    if type(final) is not ProvisionalCheckCandidateV1 or final != provisional:
        raise DispatchCheckReissueHold("final check/read closure differs")
    for item in final.positive_reads:
        row = db.execute(
            "SELECT revision,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?",
            (item.ref, *namespace.as_tuple),
        ).fetchone()
        if row != (item.version, 1):
            raise DispatchCheckReissueHold("final positive read changed")
    if (any(item.query.namespace != namespace
            or item.query.scope_ref != "all"
            or item.query.revision != provisional.graph_epoch
            or item.matching_count != 0
            for item in final.negative_queries)
            or len({item.check_kind for item in final.checks}) != len(final.checks)
            or any(item.coverage != "full" or item.result != "pass"
                   or item.valid_until < now_utc for item in final.checks)):
        raise DispatchCheckReissueHold("final negative coverage or check is incomplete")
    if (type(detail) is PostC02FinalReissueV2 or artifact):
        if detail.graph_receipt != final_receipt:
            raise DispatchCheckReissueHold("final post-C02 event receipt differs")
        return detail
    return None


__all__ = [
    "DispatchCheckReissueHold", "NegativeQueryClosureV1",
    "ProvisionalCheckCandidateV1", "PostC02FinalReissueV2",
    "reissue_and_require_identical_checks",
]
