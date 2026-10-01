"""Installed D13 factories shared by W01 and independent Authority assembly.

Profiles supply pinned policy data, not callable verifier objects. Each reader
constructs its own concrete verifier for its own current SQLite transaction.
"""
from ..authority_service.d13_wire_evidence_v1 import (
    D13ForegroundBudgetBindingV1, D13ForegroundBudgetPreparationV1,
    D13NaturalReservedSelectionV1, InstalledD13WireEvidencePortV1,
    InstalledD13WirePolicyV1, installed_d13_wire_policy_from_payload_v1,
    install_d13_wire_evidence_schema_v1, record_signed_d13_wire_evidence_v1,
    validate_reserved_d13_natural_selection_v1,
)
from ..authority_service.d13_paid_block_verifier_v1 import (
    build_installed_d13_paid_block_verifier_v1,
)


def build_installed_d13_wire_evidence_port_v1(db, *, policy, foreground_budget,
        resource_issuer, budget_issuer, paid_verifier=None):
    if policy is None:
        return None
    return InstalledD13WireEvidencePortV1(db, policy=policy,
        foreground_budget=foreground_budget, resource_issuer=resource_issuer,
        budget_issuer=budget_issuer, paid_verifier=paid_verifier)
