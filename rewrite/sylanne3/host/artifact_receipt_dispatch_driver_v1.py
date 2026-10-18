"""One actual Artifact completion receipt through the shared P2 handoff.

The fixed text is grounded in the new D06 completion Source. This driver never
reads old reply ownership or creates a replacement effect after an unknown.
"""
from ..graph_worker import GraphWorker
from ..contracts import EventConflict,StaleRead
from ..graph_coordinator import UnavailableGuard
from ..authority_service.contract import AuthorityUnavailable
from ..dispatch_runtime import HandoffUncertain
from .v2_fence_port import V2FenceOutcomeUnknown
from .authority_profile import AdminInstallationBundle
from .private_reply_dispatch_driver import (InstalledPrivateReplyContinuationV1,
    OriginalPrivateReplyDispatchV1,PrivateReplyDispatchHold,PrivateReplyDispatchResultV1)


class InstalledArtifactReceiptContinuationV1(InstalledPrivateReplyContinuationV1):
    """Exact registered Artifact family; the shared sender still repeats P2 checks."""


class ArtifactReceiptDispatchDriverV1:
    def __init__(self,worker,bootstrap,bundle,continuation):
        if (type(worker) is not GraphWorker or type(bundle) is not AdminInstallationBundle
                or type(continuation) is not InstalledArtifactReceiptContinuationV1
                or continuation._worker is not worker or continuation._policy is not bundle.installation_policy
                or bundle.artifact_phase_observer is None):
            raise ValueError('Artifact receipt driver needs its exact installed worker/bundle/continuation')
        self.worker,self.bootstrap,self.bundle,self.continuation=worker,bootstrap,bundle,continuation

    async def dispatch(self,*,c02_operation_id,source_ref):
        try:
            prepared=await self.worker.call(lambda graph:graph.prepare_current_artifact_receipt_dispatch_v1(
                self.bootstrap,self.bundle,c02_operation_id=c02_operation_id,source_ref=source_ref))
            if prepared.get('status')!='artifact_receipt_dispatch_committed':
                return PrivateReplyDispatchResultV1('hold','actual Artifact receipt dispatch admission not committed')
            original=await self.worker.call(lambda graph:graph.read_committed_artifact_receipt_dispatch_v1(
                self.bootstrap,self.bundle,operation_id=prepared['operation_id'],
                authority=self.continuation._authority,lease=self.continuation._lease))
            if type(original) is not OriginalPrivateReplyDispatchV1:
                raise PrivateReplyDispatchHold('actual Artifact receipt dispatch identity unavailable')
        except (HandoffUncertain,V2FenceOutcomeUnknown) as exc:
            return PrivateReplyDispatchResultV1('unknown',str(exc))
        except (PrivateReplyDispatchHold,UnavailableGuard,AuthorityUnavailable,EventConflict,StaleRead) as exc:
            return PrivateReplyDispatchResultV1('hold',str(exc))
        try:
            effect=await self.continuation.read_recovery_state(original)
            if effect.state=='observed':
                return PrivateReplyDispatchResultV1('observed','same original effect already observed; no platform retry',original)
            if effect.state=='unresolved':
                return PrivateReplyDispatchResultV1('unknown','same original effect unresolved; retain reservation and reconcile',original)
            outcome=await self.continuation.dispatch(original)
        except (HandoffUncertain,V2FenceOutcomeUnknown) as exc:
            return PrivateReplyDispatchResultV1('unknown',str(exc),original)
        except Exception as exc:
            return PrivateReplyDispatchResultV1('hold',str(exc),original)
        if outcome=='replay':
            return PrivateReplyDispatchResultV1('observed','durable original handoff replay; no platform retry',original)
        reason=('adapter accepted the fixed receipt; delivery remains unverified' if outcome=='accepted'
            else 'actual recipient delivery observation' if outcome=='delivered' else 'original platform outcome unresolved')
        return PrivateReplyDispatchResultV1(outcome,reason,original)
