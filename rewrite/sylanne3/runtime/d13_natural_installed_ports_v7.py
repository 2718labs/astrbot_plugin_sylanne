"""Actual installed v7 current paid/count/budget factory; no profile setter or legacy mode switch."""
from ..authority_service.d13_derived_paid_block_verifier_v2 import build_installed_d13_derived_paid_block_verifier_v2
from ..authority_service.d13_wire_evidence_v7 import InstalledD13WireEvidencePortV7,InstalledD13WirePolicyV7
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from ..host.model_workflows_v8 import AdminModelWorkflowsV8
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION,FrozenNaturalReplyRequestV7
from ..runtime_contracts import canonical_digest
from .d13_natural_installed_ports_v1 import _current_source_ref
from .installed_d13_wire_evidence_v1 import D13ForegroundBudgetPreparationV1,D13ForegroundBudgetBindingV1
from .natural_reply_job_v2 import natural_job_ids_v2,read_original_preparation
from .jobs import get_job


def build_current_natural_d13_ports_v7(db,*,bundle,resource_issuer,budget_issuer,c02_operation_id,plan,activation_generation,
        now_utc,original=None,authority_store=None,max_slots=256,_authority_replay=None):
    if (not db.in_transaction or type(bundle.model_workflows) not in {AdminModelWorkflowsV7, AdminModelWorkflowsV8}
            or bundle.model_workflows.natural_generation is None
            or bundle.model_workflows.natural_generation.template_version!=TEMPLATE_VERSION
            or original is not None and type(original) is not FrozenNaturalReplyRequestV7):
        raise ValueError('v7 installed factories require actual v7 workflow/template/original')
    policy=bundle.installation_policy
    if plan.namespace!=policy.namespace:
        raise ValueError('v7 current plan crossed its installation namespace')
    main=bundle.model_workflows.reply
    if _authority_replay is None:
        paid=None if main is None else build_installed_d13_derived_paid_block_verifier_v2(db,
            installation=D13PrecompressionInstallationV1(policy.installation_id,main.provider_id,main.model_id,
                main.provider_config_digest,main.max_output_tokens),resource_issuer=resource_issuer,budget_issuer=budget_issuer,
            namespace=policy.namespace,scene_ref=plan.scene_id,conversation_ref=plan.audience_id,now_utc=now_utc,
            activation_generation=activation_generation,authority_store=authority_store,max_slots=max_slots)
    else:
        from .installed_d13_natural_frame_v7 import _AuthorityCurrentNaturalFrameV7
        if type(_authority_replay)is not _AuthorityCurrentNaturalFrameV7:
            raise ValueError('actual Authority V7 original replay required')
        _authority_replay._actual()
        if (_authority_replay.work.db is not db or _authority_replay.frozen is not original
                or _authority_replay.parent_original_id!=c02_operation_id
                or _authority_replay.issuer._bundle is not bundle or _authority_replay.now_utc!=now_utc
                or _authority_replay.phase!='wire_verify'):
            raise ValueError('Authority V7 factory crossed its current original/bundle/clock')
        paid,_blocks=_authority_replay.paid_reader.require_current_v6(_authority_replay.work)
    if bundle.d13_wire_policy is None:
        return None,paid
    if type(bundle.d13_wire_policy) is not InstalledD13WirePolicyV7 or bundle.d13_wire_policy.max_slots!=max_slots or paid is None:
        raise ValueError('v7 actual counter policy/current paid factory missing or mismatched')
    if original is None:
        if now_utc is None:
            raise ValueError("D13 fresh natural selection requires the actual current clock")
        from .natural_reply_budget_v3 import resolve_natural_reply_budget_for_new_admission_v3
        source_ref = _current_source_ref(db, policy.namespace, c02_operation_id)
        _lease, grant = resolve_natural_reply_budget_for_new_admission_v3(db,
            namespace=policy.namespace, c02_operation_id=c02_operation_id,
            source_ref=source_ref, issuer=budget_issuer, installed_bundle=bundle,
            now_utc=now_utc)
        saved = natural_job_ids_v2(policy.namespace, c02_operation_id, "generation")
        suffix = canonical_digest({"schema": "sylanne.d09.natural-generation-identity.v2",
            "namespace": policy.namespace, "c02_operation_id": c02_operation_id,
            "source_ref": source_ref})[:48]
        budget = D13ForegroundBudgetPreparationV1(policy.namespace, grant.lease_id,
            grant.grant_id, grant.version, canonical_digest(grant),
            dict(bundle.model_workflows.natural_generation.quote_ceiling),
            "natural-generation-activity:" + suffix, saved[4])
    else:
        saved = read_original_preparation(db, policy.namespace, c02_operation_id, "generation")
        if saved is None or saved.frozen != original:
            raise ValueError("D13 replay must read its exact durable foreground original")
        job = get_job(db, saved.seal.job_id)
        quote_id, version = job.operator_versions["resource_quote"].rsplit(":", 1)
        from ..authority_service.current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
        handled,reservation=read_bound_authority_graph_attachment_v3(db,table='runtime_budget_reservations',
            columns=('digest',),key_columns=('lease_id','operation_id'),
            key=(saved.seal.parent_budget_lease_id,saved.seal.reservation_operation_id))
        if not handled:
            reservation = db.execute("SELECT digest FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (saved.seal.parent_budget_lease_id, saved.seal.reservation_operation_id)).fetchone()
        if reservation is None:
            raise ValueError("D13 foreground original reservation absent")
        budget = D13ForegroundBudgetBindingV1(quote_id, int(version), saved.seal.parent_budget_lease_id,
            saved.seal.reservation_operation_id, reservation[0])
    return InstalledD13WireEvidencePortV7(db,policy=bundle.d13_wire_policy,foreground_budget=budget,
        resource_issuer=resource_issuer,budget_issuer=budget_issuer,c02_operation_id=c02_operation_id),paid
