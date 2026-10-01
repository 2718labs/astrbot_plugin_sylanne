"""Compose foreground D13 readers from the installed profile in the held tx."""
from __future__ import annotations
from ..model_broker.d13_precompression import D13PrecompressionInstallationV1
from ..runtime_contracts import canonical_digest
from .installed_d13_wire_evidence_v1 import (
    build_installed_d13_paid_block_verifier_v1, build_installed_d13_wire_evidence_port_v1,
    D13ForegroundBudgetPreparationV1, D13ForegroundBudgetBindingV1)
from .natural_reply_job_v2 import natural_job_ids_v2, read_original_preparation
from .jobs import get_job


def build_current_natural_d13_ports_v1(db, *, bundle, resource_issuer, budget_issuer,
        c02_operation_id, original=None, authority_store=None, max_slots=64):
    if not db.in_transaction:
        raise ValueError("D13 installed selection needs the current Graph transaction")
    policy = bundle.installation_policy
    main = bundle.model_workflows.reply
    paid = (None if main is None else build_installed_d13_paid_block_verifier_v1(db,
        installation=D13PrecompressionInstallationV1(policy.installation_id, main.provider_id,
            main.model_id, main.provider_config_digest, main.max_output_tokens),
        resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        authority_store=authority_store, max_slots=max_slots))
    if bundle.d13_wire_policy is None:
        return None, paid
    if bundle.d13_wire_policy.max_slots != max_slots:
        raise ValueError("D13 pinned counter and current frame source page size differ")
    if original is None:
        grant = budget_issuer.current_budget_grant(db, policy.root_grant.lease_id)
        saved = natural_job_ids_v2(policy.namespace, c02_operation_id, "generation")
        suffix = canonical_digest({"schema": "sylanne.d09.natural-generation-identity.v2",
            "namespace": policy.namespace, "c02_operation_id": c02_operation_id,
            "source_ref": _current_source_ref(db, policy.namespace, c02_operation_id)})[:48]
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
        reservation = db.execute("SELECT digest FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (saved.seal.parent_budget_lease_id, saved.seal.reservation_operation_id)).fetchone()
        if reservation is None:
            raise ValueError("D13 foreground original reservation absent")
        budget = D13ForegroundBudgetBindingV1(quote_id, int(version), saved.seal.parent_budget_lease_id,
            saved.seal.reservation_operation_id, reservation[0])
    return build_installed_d13_wire_evidence_port_v1(db, policy=bundle.d13_wire_policy,
        foreground_budget=budget, resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        paid_verifier=paid), paid


def _current_source_ref(db, namespace, c02_id):
    from .c02_bundle_codec import c02_bundle_from_wire
    row = db.execute("SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, c02_id)).fetchone()
    if row is None:
        raise ValueError("D13 foreground source C02 original absent")
    source_refs = c02_bundle_from_wire(row[0]).envelope.source_qualification.source_refs
    if len(source_refs) != 1:
        raise ValueError("D13 foreground requires its exact current source")
    return source_refs[0]
