"""Authority independently reconstructs D13 V4 history from its installed pins."""
from __future__ import annotations
from dataclasses import dataclass

from ..model_broker.natural_reply import NaturalReplyInstallationV2
from ..model_broker.natural_reply_history_v4 import FrozenNaturalReplyRequestV4, TEMPLATE_VERSION
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

    def current_v4(self, db, *, frozen, parent_original_id, now_utc):
        """Read only; other existing Authority checks still own D09/worker gates."""
        from ..runtime.d13_natural_installed_ports_v1 import build_current_natural_d13_ports_v1
        try:
            if not db.in_transaction or type(frozen) is not FrozenNaturalReplyRequestV4:
                return None
            bundle = self._bundle
            workflow = bundle.model_workflows.natural_generation
            if (workflow is None or workflow.template_version != TEMPLATE_VERSION
                    or frozen.input.plan.namespace != bundle.installation_policy.namespace):
                return None
            installed = NaturalReplyInstallationV2(bundle.installation_policy.installation_id,
                workflow.provider_config_digest, workflow.provider_id, workflow.model_id, workflow.max_output_tokens)
            if installed != frozen.installation:
                return None
            max_slots = bundle.d13_precompression.max_slots if bundle.d13_precompression is not None else 64
            wire, paid = build_current_natural_d13_ports_v1(db, bundle=bundle,
                resource_issuer=self._issuer.resource_issuer, budget_issuer=self._issuer,
                c02_operation_id=parent_original_id, original=frozen,
                authority_store=self._store, max_slots=max_slots)
            result, reads, decision = freeze_current_natural_frame_v4(db,
                namespace=bundle.installation_policy.namespace, plan=frozen.input.plan,
                question=frozen.input.question, installation=installed, now_utc=now_utc,
                expires_at_utc=frozen.input.expires_at_utc,
                activation_generation=frozen.input.history_selection.activation_generation,
                max_slots=max_slots, original=frozen, installed_wire_port=wire, paid_verifier=paid)
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
