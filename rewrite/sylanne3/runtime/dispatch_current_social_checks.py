"""Recompute D03/D05 dispatch checks from a complete current graph projection.

This verifies existing receipts only.  The caller must hold the graph write
transaction and the independent Authority fence through final admission.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math

from ..runtime_storage_v3 import read_graph_row_v3
from ..domains.d03.context import ContextProvider, RoleBindingRequest
from ..domains.d05.relationship import RelationshipProvider
from ..domains.d08 import ActionIntent, ActionSchema, ActionSchemaRecord
from ..graph_types import AtomKey, GraphSnapshot
from ..runtime_contracts import CheckReceipt, QueryEpoch
from .dispatch_current_projection import (
    CurrentDispatchProjectionV1, derive_current_domain_reads,
    read_current_dispatch_projection,
)


@dataclass(frozen=True)
class CurrentSocialChecksV1:
    status: str
    verified: bool
    reason: str


def verify_current_social_checks(
    db, snapshot: GraphSnapshot, projection: CurrentDispatchProjectionV1,
    intent: ActionIntent, schema: ActionSchemaRecord,
    role_receipt: CheckReceipt, boundary_receipt: CheckReceipt, *,
    context: ContextProvider, scene_ref: str, audience_scope: str,
    now_utc: float, current_catalogue_confirmed: bool = False, prepared_inventory=None,
) -> CurrentSocialChecksV1:
    """Compare D03/D05 provider results with receipts pinned to this action.

    A complete projection is re-read from SQLite while the caller's graph
    transaction is open.  The boundary provider's read verifier is bound to
    that derived read set; an issuer string or supplied receipt cannot confirm
    coverage.  Current D01 role authority remains a separate admission gate.
    """

    def hold(reason: str) -> CurrentSocialChecksV1:
        return CurrentSocialChecksV1("hold", False, reason)

    if (not db.in_transaction or type(snapshot) is not GraphSnapshot
            or type(projection) is not CurrentDispatchProjectionV1
            or type(intent) is not ActionIntent
            or type(schema) is not ActionSchemaRecord
            or type(role_receipt) is not CheckReceipt
            or type(boundary_receipt) is not CheckReceipt
            or type(context) is not ContextProvider):
        return hold("current_transaction_or_typed_inputs_missing")
    if (type(now_utc) not in (int, float) or not math.isfinite(now_utc)
            or type(scene_ref) is not str or not scene_ref.startswith("scene:")
            or type(audience_scope) is not str or not audience_scope):
        return hold("current_time_or_social_scope_invalid")
    if current_catalogue_confirmed is not True:
        return hold("current_d03_catalogue_unconfirmed")
    frozen = ActionSchema(
        schema.schema_id, schema.action_kind, schema.proactive,
        schema.required_checks,
    )
    if schema != ActionSchemaRecord.bind(intent, frozen):
        return hold("frozen_action_schema_differs")
    namespace = projection.namespace
    if len(snapshot.epochs) != 1:
        return hold("current_graph_epoch_missing")
    try:
        current = read_current_dispatch_projection(
            db, namespace, snapshot,
            QueryEpoch(namespace, "all", projection.graph_epoch), prepared_inventory=prepared_inventory,
        )
        if current != projection:
            return hold("current_social_projection_changed")
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            scene_ref, intent.action_kind, intent.purpose, now_utc, True,
        )
        role_read, boundary_read = derive_current_domain_reads(
            db, current, request, context, prepared_inventory=prepared_inventory,
        )
        role_spec = next(item for item in schema.required_checks
                         if item.check_kind == "role_binding")
        boundary_spec = next(item for item in schema.required_checks
                             if item.check_kind == "boundary")
        if (role_spec.provider_id != "d03.role_binding"
                or boundary_spec.provider_id != "d05.boundary"):
            return hold("social_check_provider_differs")
        for spec in (role_spec, boundary_spec):
            key = AtomKey.from_token(spec.criteria_version)
            atom = snapshot.get(key)
            row = read_graph_row_v3(db, columns=('revision', 'value', 'valid'), where='token=? AND bot=? AND persona=?', parameters=(key.token, *namespace.as_tuple))
            expected = next(item.version for item in spec.required_input_versions
                            if item.ref == spec.criteria_version)
            if (atom is None or row is None or not atom.valid
                    or atom.revision != expected or row[0] != expected
                    or row[2] != 1 or json.loads(row[1]) != atom.value):
                return hold("social_criteria_not_current")
        # derive_current_domain_reads covers all D05 rows.  Its default read
        # set lacks the criteria atom, which the D05 provider also requires.
        criteria = next(item for item in boundary_spec.required_input_versions
                        if item.ref == boundary_spec.criteria_version)
        boundary_read = replace(
            boundary_read,
            input_versions=boundary_read.input_versions + (criteria,),
        )
        role_check = context.provide_required_check(
            intent, role_read, valid_until=role_receipt.valid_until,
        )
        boundary_provider = RelationshipProvider(
            boundary_read_verifier=lambda observed: observed == boundary_read,
        )
        boundary_check = boundary_provider.boundary_required_check(
            intent, frozen, boundary_read,
            audience_scope=audience_scope, scene_ref=scene_ref,
            at_time=now_utc, valid_until=boundary_receipt.valid_until,
        )
    except (TypeError, ValueError, KeyError, StopIteration, json.JSONDecodeError):
        return hold("current_social_check_unavailable")
    if (role_receipt.valid_until < now_utc
            or boundary_receipt.valid_until < now_utc
            or role_check != role_receipt or boundary_check != boundary_receipt
            or role_check.result != "pass" or role_check.coverage != "full"
            or boundary_check.result != "pass" or boundary_check.coverage != "full"):
        return hold("current_social_receipt_incomplete_or_changed")
    return CurrentSocialChecksV1("verified", True, "current_d03_d05_checks")


__all__ = ["CurrentSocialChecksV1", "verify_current_social_checks"]
