"""Authority independently reconstructs D13 V4 history from its installed pins."""
from __future__ import annotations
from dataclasses import dataclass
from contextlib import closing
import secrets
import sqlite3

from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v4 import (
    FrozenNaturalReplyRequestV4, TEMPLATE_VERSION, TEMPLATE_VERSION_V5,
    INPUT_SCHEMA, INPUT_SCHEMA_V5,
)
from ..runtime.installed_d13_natural_frame_v4 import freeze_current_natural_frame_v4
from ..runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class D13AuthorityNaturalFrameReadV1:
    frozen_digest: str
    wire_digest: str
    current_reads: tuple
    budget_state: str
    proof_digest: str | None


class InstalledAuthorityD13NaturalFrameVerifierV1:
    """Never accepts a Host verifier. Holds independent installed service parts."""
    def __init__(self, *, bundle, d11_issuer, authority_store):
        from ..host.authority_profile import AdminInstallationBundle
        from ..runtime.issuers import D11BudgetJobIssuer
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        if (type(bundle) is not AdminInstallationBundle
                or type(d11_issuer) is not D11BudgetJobIssuer
                or type(authority_store) is not AuthorityV2ModelEgressStore):
            raise ValueError("Authority D13 needs its protected profile, signed issuer and independent model store")
        self._bundle, self._issuer, self._store = bundle, d11_issuer, authority_store
        self._execution = None

    def install_actual_execution_bridge_v3(self, bridge):
        from .v2_execution_bridge import AuthorityV2ExecutionBridge
        if (type(bridge) is not AuthorityV2ExecutionBridge
                or bridge.core._db is not self._store._db or bridge.core._lock is not self._store._lock
                or bridge.namespace != self._bundle.installation_policy.authority_namespace
                or bridge._owner_installation_id != self._bundle.installation_policy.installation_id
                or self._execution is not None and self._execution is not bridge):
            raise ValueError("same-batch reader requires the actual installed Core execution bridge")
        self._execution = bridge

    def prepare_continuation_v5(self, graph_path, parent_original_id, *, credential, subject, fences):
        """Collect closed Core originals before opening the consumer Graph snapshot."""
        from ..runtime.natural_same_batch_history_v3 import (
            same_batch_observation_hints_v3, NaturalSameBatchPreparedV3)
        with closing(sqlite3.connect(graph_path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            try:
                hints = same_batch_observation_hints_v3(db, self._bundle.installation_policy.namespace, parent_original_id)
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

    def current_v4(self, db, *, frozen, parent_original_id, now_utc, same_batch_prepared=None):
        """Read only; other existing Authority checks still own D09/worker gates."""
        from ..runtime.d13_natural_installed_ports_v1 import build_current_natural_d13_ports_v1
        try:
            if not db.in_transaction or type(frozen) is not FrozenNaturalReplyRequestV4:
                return None
            bundle = self._bundle
            workflow = bundle.model_workflows.natural_generation
            if (workflow is None or workflow.template_version not in {TEMPLATE_VERSION, TEMPLATE_VERSION_V5}
                    or frozen.input.plan.namespace != bundle.installation_policy.namespace):
                return None
            installed = NaturalReplyInstallationV2(bundle.installation_policy.installation_id,
                workflow.provider_config_digest, workflow.provider_id, workflow.model_id, workflow.max_output_tokens)
            if installed != frozen.installation:
                return None
            max_slots = bundle.d13_precompression.max_slots if bundle.d13_precompression is not None else 64
            if same_batch_prepared is not None:
                from ..runtime.natural_same_batch_history_v3 import verify_same_batch_history_v3
                if workflow.template_version != TEMPLATE_VERSION_V5 or frozen.input.schema != INPUT_SCHEMA_V5:
                    return None
                reads = verify_same_batch_history_v3(db, issuer=self, prepared=same_batch_prepared,
                    namespace=bundle.installation_policy.namespace, parent_original_id=parent_original_id,
                    frozen=frozen, now_utc=now_utc, max_slots=max_slots)
                return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen), frozen.model_request_digest,
                    reads, "original_paid_calls_unchanged", canonical_digest({
                        "schema": "d13.same-batch-original-read.v3", "frozen": canonical_digest(frozen),
                        "observations": same_batch_prepared.observations, "current_reads": reads}))
            wire, paid = build_current_natural_d13_ports_v1(db, bundle=bundle,
                resource_issuer=self._issuer.resource_issuer, budget_issuer=self._issuer,
                c02_operation_id=parent_original_id, original=frozen,
                authority_store=self._store, max_slots=max_slots)
            result, reads, decision = freeze_current_natural_frame_v4(db,
                namespace=bundle.installation_policy.namespace, plan=frozen.input.plan,
                question=frozen.input.question, installation=installed, now_utc=now_utc,
                expires_at_utc=frozen.input.expires_at_utc,
                activation_generation=frozen.input.history_selection.activation_generation,
                max_slots=max_slots, original=frozen, installed_wire_port=wire, paid_verifier=paid,
                input_schema=INPUT_SCHEMA_V5 if workflow.template_version == TEMPLATE_VERSION_V5 else INPUT_SCHEMA)
            if result != frozen or decision.activation_write is not None:
                return None
            if frozen.input.stable_history and decision.budget_state != "reserved_original":
                return None
            return D13AuthorityNaturalFrameReadV1(canonical_digest(frozen), frozen.model_request_digest,
                reads, decision.budget_state, decision.proof_digest)
        except Exception:
            return None


def build_authority_d13_natural_frame_verifier_v1(*, bundle, d11_issuer, authority_store):
    return InstalledAuthorityD13NaturalFrameVerifierV1(bundle=bundle,
        d11_issuer=d11_issuer, authority_store=authority_store)
