"""Independent installed Authority v7 current Source/paid/whole-wire consumer."""
from contextlib import closing
import secrets
import sqlite3
from weakref import WeakSet
from .contract import AuthorityUnavailable
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from ..host.model_workflows_v8 import AdminModelWorkflowsV8
from ..host.model_workflows_v9 import AdminModelWorkflowsV9
from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7,TEMPLATE_VERSION
from ..runtime.d13_natural_installed_ports_v7 import build_current_natural_d13_ports_v7
from ..runtime.installed_d13_natural_frame_v7 import freeze_current_natural_frame_v7
from ..runtime_contracts import canonical_digest
from .d13_natural_frame_verifier_v1 import InstalledAuthorityD13NaturalFrameVerifierV1,D13AuthorityNaturalFrameReadV1

_CONTINUATIONS_V7 = WeakSet()


def _require_actual_legacy_graph_v7(db):
    columns = {row[1] for row in db.execute("PRAGMA table_info(graph_atoms)")}
    if "value" not in columns or "value_cell_id" in columns:
        raise AuthorityUnavailable("Authority V7 continuation requires its actual same-Work segmented reader")


class _AuthoritySameBatchContinuationV7:
    def __init__(self, work, *, frozen, parent_original_id):
        from .current_authority_graph_read_v3 import (AuthorityGraphReadWorkV3,
            require_authority_prepared_generation_v3)
        if type(work) is not AuthorityGraphReadWorkV3:
            raise AuthorityUnavailable("actual independently issued Authority Work required")
        work._actual()
        issuer = getattr(work.controller.verifier, "_natural_history", None)
        if (type(issuer) is not InstalledAuthorityD13NaturalFrameVerifierV7
                or issuer._bundle.installation_policy.namespace != work.namespace
                or work.parent_original_id != parent_original_id
                or require_authority_prepared_generation_v3(work,
                    parent_original_id=parent_original_id).frozen is not frozen):
            raise AuthorityUnavailable("Authority V7 history issuer/parent/frozen/namespace differs")
        self.work, self.issuer, self.frozen, self.parent_original_id = work, issuer, frozen, parent_original_id
        self.phase, self.complete, self.prepared = "hints", False, None
        self.hints, self.frozen_digest = None, None
        _CONTINUATIONS_V7.add(self)
    def advance(self, *, meter=None):
        work = self.work
        if self not in _CONTINUATIONS_V7 or self.complete:
            raise AuthorityUnavailable("actual unfinished Authority V7 continuation required")
        work._actual()
        if self.phase == "hints":
            from .current_authority_graph_read_v3 import require_authority_same_batch_hints_v7
            if meter is None:
                raise AuthorityUnavailable("Authority V7 hints require the original local quantum")
            work.require_current(meter=meter)
            hints = require_authority_same_batch_hints_v7(work,
                parent_original_id=self.parent_original_id, frozen=self.frozen)
            if hints is None:
                self.complete = True
                return self
            if hints[0] is not self.frozen or type(hints[2]) is not tuple or len(hints[2]) > 4:
                raise AuthorityUnavailable("Authority V7 hints lost their actual saved frozen identity")
            self.hints, self.frozen_digest = hints[:3], hints[3]
            if not hints[2]:
                self.complete = True
            else:
                self.phase = "observations"
            return self
        if self.phase != "observations" or meter is not None or work.db.in_transaction:
            raise AuthorityUnavailable("Authority V7 observations must run outside the Graph transaction/quantum")
        bridge, fences = self.issuer._execution, work.controller.fences
        if (bridge is None or fences.core is not bridge.core or fences.fences is not bridge.fences
                or fences.execution is not bridge.journal or fences.deletion is not bridge.deletion):
            raise AuthorityUnavailable("Authority V7 observations require the actual original bridge")
        work._check_permission_v3()
        observations = tuple(bridge.read_current_observation_receipt_v1(
            credential=work.credential, subject=work.subject, effect_id=effect_id)
            for _, effect_id in self.hints[2])
        work._check_permission_v3()
        from ..runtime.natural_same_batch_history_v3 import NaturalSameBatchPreparedV3
        self.prepared = NaturalSameBatchPreparedV3(self.issuer, work.namespace,
            self.parent_original_id, self.frozen_digest, work.permit, observations)
        self.complete = True
        return self
    def release_payload_v3(self):
        _CONTINUATIONS_V7.discard(self)
        self.hints = self.frozen = self.prepared = None


def begin_authority_same_batch_continuation_v7(work, *, frozen, parent_original_id):
    return _AuthoritySameBatchContinuationV7(work, frozen=frozen, parent_original_id=parent_original_id)


class InstalledAuthorityD13NaturalFrameVerifierV7(InstalledAuthorityD13NaturalFrameVerifierV1):
    def __init__(self,*,bundle,d11_issuer,authority_store):
        super().__init__(bundle=bundle,d11_issuer=d11_issuer,authority_store=authority_store)
        if (type(bundle.model_workflows) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} or bundle.model_workflows.natural_generation is None
                or bundle.model_workflows.natural_generation.template_version!=TEMPLATE_VERSION):
            raise ValueError('Authority v7 reader requires its actual new installed workflow/template')

    def prepare_continuation_v7(self, graph_path, parent_original_id, *, credential, subject, fences, work=None, frozen=None):
        """Collect closed Core originals before opening the consumer Graph snapshot."""
        if work is not None:
            if (work.credential is not credential or work.subject != subject or work.controller.fences is not fences
                    or work.controller.location._graph_db_path != graph_path
                    or getattr(work.controller.verifier, "_natural_history", None) is not self):
                raise AuthorityUnavailable("Authority V7 prepare crossed its actual consumer Work/permit")
            return begin_authority_same_batch_continuation_v7(work, frozen=frozen,
                parent_original_id=parent_original_id)
        from ..runtime.natural_same_batch_history_v7 import same_batch_observation_hints_v7
        from ..runtime.natural_same_batch_history_v3 import NaturalSameBatchPreparedV3
        with closing(sqlite3.connect(graph_path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            _require_actual_legacy_graph_v7(db)
            db.execute("BEGIN")
            try:
                hints = same_batch_observation_hints_v7(db, self._bundle.installation_policy.namespace, parent_original_id)
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


    def current_v7(self,db,*,frozen,parent_original_id,now_utc,same_batch_prepared=None):
        if not db.in_transaction or type(frozen) is not FrozenNaturalReplyRequestV7:
            return None
        from .current_authority_graph_read_v3 import require_current_authority_graph_read_work_v3
        work = require_current_authority_graph_read_work_v3(db,
            self._bundle.installation_policy.namespace, parent_original_id=parent_original_id, frozen=frozen)
        if work is not None:
            if getattr(work.controller.verifier, "_natural_history", None) is not self:
                raise AuthorityUnavailable("Authority V7 current frame has another actual installed issuer")
            from .current_authority_graph_read_v3 import require_authority_current_natural_frame_v7
            return require_authority_current_natural_frame_v7(work, issuer=self, frozen=frozen,
                parent_original_id=parent_original_id, now_utc=now_utc,
                same_batch_prepared=same_batch_prepared)
        _require_actual_legacy_graph_v7(db)
        bundle=self._bundle;workflow=bundle.model_workflows.natural_generation
        installed=NaturalReplyInstallationV2(bundle.installation_policy.installation_id,workflow.provider_config_digest,
            workflow.provider_id,workflow.model_id,workflow.max_output_tokens)
        if installed!=frozen.installation or frozen.input.plan.namespace!=bundle.installation_policy.namespace:
            return None
        max_slots=bundle.d13_wire_policy.max_slots if bundle.d13_wire_policy is not None else 256
        if same_batch_prepared is not None:
            from ..runtime.natural_same_batch_history_v7 import verify_same_batch_history_v7
            reads=verify_same_batch_history_v7(db,issuer=self,prepared=same_batch_prepared,
                namespace=bundle.installation_policy.namespace,parent_original_id=parent_original_id,frozen=frozen,
                now_utc=now_utc,max_slots=max_slots)
            return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen),frozen.model_request_digest,reads,
                'original_paid_calls_unchanged',canonical_digest({'schema':'d13.same-batch-original-read.v7',
                    'frozen':canonical_digest(frozen),'observations':same_batch_prepared.observations,'current_reads':reads}))
        wire,paid=build_current_natural_d13_ports_v7(db,bundle=bundle,resource_issuer=self._issuer.resource_issuer,
            budget_issuer=self._issuer,c02_operation_id=parent_original_id,plan=frozen.input.plan,now_utc=now_utc,
            activation_generation=frozen.input.history_selection.activation_generation,original=frozen,
            authority_store=self._store,max_slots=max_slots)
        result,reads,decision=freeze_current_natural_frame_v7(db,namespace=bundle.installation_policy.namespace,
            plan=frozen.input.plan,question=frozen.input.question,installation=installed,now_utc=now_utc,
            expires_at_utc=frozen.input.expires_at_utc,activation_generation=frozen.input.history_selection.activation_generation,
            max_slots=max_slots,original=frozen,installed_wire_port=wire,paid_verifier=paid,
            policy_digest=frozen.input.history_selection.policy_digest)
        if result!=frozen or decision.activation_writes or frozen.input.stable_history and decision.budget_state!='reserved_original':
            return None
        return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen),frozen.model_request_digest,reads,
            decision.budget_state,decision.proof_digest)


def build_authority_d13_natural_frame_verifier_v7(*,bundle,d11_issuer,authority_store):
    return InstalledAuthorityD13NaturalFrameVerifierV7(bundle=bundle,d11_issuer=d11_issuer,authority_store=authority_store)
