"""Independent installed Authority v6 current Source/paid/whole-wire consumer."""
from contextlib import closing
import secrets
import sqlite3
from ..host.model_workflows_v6 import AdminModelWorkflowsV6
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6,TEMPLATE_VERSION
from ..runtime.d13_natural_installed_ports_v6 import build_current_natural_d13_ports_v6
from ..runtime.installed_d13_natural_frame_v6 import freeze_current_natural_frame_v6
from ..runtime_contracts import canonical_digest
from .d13_natural_frame_verifier_v1 import InstalledAuthorityD13NaturalFrameVerifierV1,D13AuthorityNaturalFrameReadV1

class InstalledAuthorityD13NaturalFrameVerifierV6(InstalledAuthorityD13NaturalFrameVerifierV1):
    def __init__(self,*,bundle,d11_issuer,authority_store):
        super().__init__(bundle=bundle,d11_issuer=d11_issuer,authority_store=authority_store)
        if (type(bundle.model_workflows) is not AdminModelWorkflowsV6 or bundle.model_workflows.natural_generation is None
                or bundle.model_workflows.natural_generation.template_version!=TEMPLATE_VERSION):
            raise ValueError('Authority v6 reader requires its actual new installed workflow/template')

    def prepare_continuation_v6(self, graph_path, parent_original_id, *, credential, subject, fences):
        """Collect closed Core originals before opening the consumer Graph snapshot."""
        from ..runtime.natural_same_batch_history_v6 import same_batch_observation_hints_v6
        from ..runtime.natural_same_batch_history_v3 import NaturalSameBatchPreparedV3
        with closing(sqlite3.connect(graph_path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                hints = same_batch_observation_hints_v6(db, self._bundle.installation_policy.namespace, parent_original_id)
            finally:
                db.execute("ROLLBACK")
        if hints is None or not hints[2]:
            return None
        bridge = self._execution
        if (bridge is None or credential is None or type(subject) is not str
                or fences.core is not bridge.core or fences.fences is not bridge.fences
                or fences.execution is not bridge.journal or fences.deletion is not bridge.deletion):
            raise ValueError("same-batch independent execution reader is unavailable")
        anchor = fences.current_anchor(credential=credential, subject=subject)
        operation_id = "same-batch-read:" + secrets.token_hex(16)
        permit = fences.begin_fence(credential=credential, subject=subject,
            holder=self._bundle.installation_policy.administrator_holder,
            operation="read", operation_id=operation_id, expected_anchor=anchor)
        try:
            fences.validate_fence(credential=credential, subject=subject, permit=permit)
            observations = tuple(bridge.read_current_observation_receipt_v1(
                credential=credential, subject=subject, effect_id=effect_id) for _, effect_id in hints[2])
            fences.validate_fence(credential=credential, subject=subject, permit=permit)
            return NaturalSameBatchPreparedV3(self, self._bundle.installation_policy.namespace,
                parent_original_id, canonical_digest(hints[0]), permit, observations)
        finally:
            fences.finish_fence(credential=credential, subject=subject, permit=permit,
                request_id="finish:" + operation_id,
                request_digest="sha256:" + canonical_digest({"action": "finish-same-batch-read", "permit": permit}))


    def current_v6(self,db,*,frozen,parent_original_id,now_utc,same_batch_prepared=None):
        if not db.in_transaction or type(frozen) is not FrozenNaturalReplyRequestV6:
            return None
        bundle=self._bundle;workflow=bundle.model_workflows.natural_generation
        installed=NaturalReplyInstallationV2(bundle.installation_policy.installation_id,workflow.provider_config_digest,
            workflow.provider_id,workflow.model_id,workflow.max_output_tokens)
        if installed!=frozen.installation or frozen.input.plan.namespace!=bundle.installation_policy.namespace:
            return None
        max_slots=bundle.d13_wire_policy.max_slots if bundle.d13_wire_policy is not None else 256
        if same_batch_prepared is not None:
            from ..runtime.natural_same_batch_history_v6 import verify_same_batch_history_v6
            reads=verify_same_batch_history_v6(db,issuer=self,prepared=same_batch_prepared,
                namespace=bundle.installation_policy.namespace,parent_original_id=parent_original_id,frozen=frozen,
                now_utc=now_utc,max_slots=max_slots)
            return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen),frozen.model_request_digest,reads,
                'original_paid_calls_unchanged',canonical_digest({'schema':'d13.same-batch-original-read.v6',
                    'frozen':canonical_digest(frozen),'observations':same_batch_prepared.observations,'current_reads':reads}))
        wire,paid=build_current_natural_d13_ports_v6(db,bundle=bundle,resource_issuer=self._issuer.resource_issuer,
            budget_issuer=self._issuer,c02_operation_id=parent_original_id,plan=frozen.input.plan,now_utc=now_utc,
            activation_generation=frozen.input.history_selection.activation_generation,original=frozen,
            authority_store=self._store,max_slots=max_slots)
        result,reads,decision=freeze_current_natural_frame_v6(db,namespace=bundle.installation_policy.namespace,
            plan=frozen.input.plan,question=frozen.input.question,installation=installed,now_utc=now_utc,
            expires_at_utc=frozen.input.expires_at_utc,activation_generation=frozen.input.history_selection.activation_generation,
            max_slots=max_slots,original=frozen,installed_wire_port=wire,paid_verifier=paid,
            policy_digest=frozen.input.history_selection.policy_digest)
        if result!=frozen or decision.activation_writes or frozen.input.stable_history and decision.budget_state!='reserved_original':
            return None
        return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen),frozen.model_request_digest,reads,
            decision.budget_state,decision.proof_digest)


def build_authority_d13_natural_frame_verifier_v6(*,bundle,d11_issuer,authority_store):
    return InstalledAuthorityD13NaturalFrameVerifierV6(bundle=bundle,d11_issuer=d11_issuer,authority_store=authority_store)
