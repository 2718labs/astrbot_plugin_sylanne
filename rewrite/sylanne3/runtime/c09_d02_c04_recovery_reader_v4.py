"""Recover one fixed Body charge from installed, signed C04 originals.

The caller owns a frozen business SQLite read transaction. The returned fact
contains the exact binary64 price and commitments, never a rounded integer.
"""

from __future__ import annotations

import math
import sqlite3

from ..authority_service.internal_work_service import AuthorityInternalWorkService
from ..authority_service.internal_work_contract import InternalWorkTerminalProofV1
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..domains.d02.c04_fixed_component_cost import read_c04_body_cost_original_v1
from ..runtime_contracts import NamespaceId, canonical_digest
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c09_d11_c04_recovery_reader_v4 import read_current_c04_d11_recovery_fact_v4
from .c09_storage_rebase_contract_v1 import SanitizedD02FactV4
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from .issuers import D02ResourceIssuer


class C09D02RecoveryHold(ValueError):
    """The original fixed charge or its signed completion is unavailable."""


def read_current_c04_d02_recovery_fact_v4(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    issuer: D02ResourceIssuer, body_authority: D02BodyQuoteAuthority,
    authority: AuthorityInternalWorkService,
    prepared_proof: InternalWorkTerminalProofV1 | None = None,
) -> SanitizedD02FactV4:
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(operation_id) is not str or not operation_id
            or type(issuer) is not D02ResourceIssuer
            or type(body_authority) is not D02BodyQuoteAuthority
            or type(authority) is not AuthorityInternalWorkService):
        raise C09D02RecoveryHold("installed D02 original readers unavailable")
    return read_c04_d02_recovery_fact_connection_v4(
        db, namespace=namespace, operation_id=operation_id, issuer=issuer, authority=authority, prepared_proof=prepared_proof, body_authority=body_authority)


__all__ = ["C09D02RecoveryHold", "read_current_c04_d02_recovery_fact_v4"]


def read_c04_d02_recovery_fact_connection_v4(db, *, namespace, operation_id, issuer, authority, prepared_proof=None, body_authority):
    from ..authority_service.c09_installed_original_verifiers_v1 import InstalledC09OriginalVerifierV1
    from .c09_d11_c04_recovery_reader_v4 import read_c04_d11_recovery_fact_connection_v4
    if (not db.in_transaction or type(authority) not in {AuthorityInternalWorkService, InstalledC09OriginalVerifierV1}
            or (type(authority) is InstalledC09OriginalVerifierV1 and (authority.kind != "internal" or prepared_proof is None))):
        raise C09D02RecoveryHold("actual installed original verifier and pinned snapshot required")
    try:
        prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
        original = read_c04_body_cost_original_v1(db, namespace, operation_id)
        cpu = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
        if prepared is None or original is None or cpu is None:
            raise C09D02RecoveryHold("committed C04 D02 original absent")
        binding = prepared.binding
        if (original.binding_digest != binding.binding_digest
                or original.operation_id != binding.operation_id
                or original.proof_digest != cpu.proof_digest
                or original.component_receipt_ref !=
                   "internal-work:component:" + binding.binding_digest):
            raise C09D02RecoveryHold("D02 committed original binding differs")
        # This also verifies the installed V2/V3 terminal signature and the
        # independently committed D11 reserve/settle originals.
        read_c04_d11_recovery_fact_connection_v4(
            db, namespace=namespace, operation_id=operation_id,
            issuer=issuer, authority=authority, prepared_proof=prepared_proof,
        )
        quote = issuer.original_signed_quote(
            db, binding.resource_quote_ref, binding.resource_quote_version)
        if (quote.d02_settlement_refs != (original.settlement_ref,)
                or canonical_digest(quote) != binding.resource_quote_digest):
            raise C09D02RecoveryHold("signed D02 quote settlement differs")
        body_quote = body_authority.original_body_quote(
            db, binding.body_quote_ref, binding.body_quote_version,
            quote, operation_id)
        components = tuple(component for component in body_quote.components
                           if component.component_id == binding.component_id)
        if (len(components) != 1 or components[0].duration_rate != 0
                or not math.isfinite(components[0].fixed_cost)
                or components[0].fixed_cost <= 0
                or type(original.fixed_cost) is not float
                or original.fixed_cost.hex() != components[0].fixed_cost.hex()
                or original.outcome_id !=
                   "internal-work-outcome:" + binding.execution_id):
            raise C09D02RecoveryHold("fixed component price or outcome differs")
        outcome = issuer.qualified_outcome(quote, db)
        if (outcome.outcome_id != original.outcome_id
                or outcome.provider_receipt_ref != cpu.terminal_receipt_ref
                or not outcome.execution_revoked):
            raise C09D02RecoveryHold("signed completed outcome differs")
        return SanitizedD02FactV4(
            quote_id=body_quote.quote_id,
            component_id=binding.component_id,
            outcome_id=outcome.outcome_id,
            settlement_id=original.settlement_ref,
            quote_commitment=canonical_digest(body_quote),
            completed_commitment=original.proof_digest,
            outcome_commitment=canonical_digest(outcome),
            settlement_commitment=original.writes_digest,
            fixed_cost_hex=original.fixed_cost.hex(),
        )
    except C09D02RecoveryHold:
        raise
    except Exception as exc:
        raise C09D02RecoveryHold("current C04 D02 originals failed verification") from exc
