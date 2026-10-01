"""D05 boundary receipt for one graph-read, pre-batch private reply."""

from __future__ import annotations

from dataclasses import dataclass, replace
import math

from .relationship import BoundaryRuleReadSet, RelationshipProvider
from ..d08 import ActionIntent, ActionSchema
from ...runtime_contracts import CheckReceipt


@dataclass(frozen=True, slots=True)
class PrebatchBoundaryResultV1:
    status: str
    missing: tuple[str, ...]
    receipt: CheckReceipt | None


def issue_prebatch_boundary_check_v1(
    intent: ActionIntent, schema: ActionSchema,
    read_set: BoundaryRuleReadSet, *,
    audience_scope: str, scene_ref: str, now_utc: float,
    valid_until_utc: float | None = None,
) -> PrebatchBoundaryResultV1:
    """Use the D05 read derived from the caller's current full graph query.

    This function cannot authenticate a graph read by itself. The D03/W01
    caller must derive ``read_set`` from the same write-locked E+1 snapshot and
    reissue it in the final receipt hook. No send authority is returned.
    """
    def hold(reason: str, receipt: CheckReceipt | None = None):
        return PrebatchBoundaryResultV1("hold", (reason,), receipt)

    if (type(intent) is not ActionIntent or type(schema) is not ActionSchema
            or type(read_set) is not BoundaryRuleReadSet
            or type(audience_scope) is not str or not audience_scope
            or type(scene_ref) is not str or not scene_ref.startswith("scene:")):
        return hold("d05.typed_staged_action_and_current_route")
    expiry = now_utc + 1.0 if valid_until_utc is None else valid_until_utc
    if (type(expiry) not in (int, float) or not math.isfinite(expiry)
            or expiry <= now_utc):
        return hold("d05.current_check_deadline_unavailable")
    if any(rule.subject_persona_ref == f"persona:{read_set.namespace.persona_id}"
           and rule.target_entity_ref == intent.target_ref
           and rule.action_kind == intent.action_kind
           and (rule.scene_ref is None or rule.scene_ref == scene_ref)
           and rule.audience_scope != audience_scope
           for rule in read_set.rules):
        return hold("d05.audience_scope_mapping_unavailable")
    specs = tuple(item for item in intent.required_checks
                  if (item.check_kind, item.provider_id) ==
                  ("boundary", "d05.boundary"))
    if len(specs) != 1:
        return hold("d05.frozen_boundary_spec")
    spec = specs[0]
    criteria = tuple(item for item in spec.required_input_versions
                     if item.ref == spec.criteria_version)
    if len(criteria) != 1:
        return hold("d05.current_criteria_version")
    read_set = replace(read_set, input_versions=read_set.input_versions + criteria)
    try:
        receipt = RelationshipProvider(
            boundary_read_verifier=lambda observed: observed == read_set,
        ).boundary_required_check(
            intent, schema, read_set, audience_scope=audience_scope,
            scene_ref=scene_ref, at_time=now_utc,
            valid_until=expiry,
        )
    except (TypeError, ValueError, StopIteration):
        return hold("d05.current_boundary_provider_unavailable")
    if (receipt.result, receipt.coverage) != ("pass", "full"):
        return hold("d05.current_boundary_not_pass", receipt)
    return PrebatchBoundaryResultV1("check_pass", (), receipt)


__all__ = ["PrebatchBoundaryResultV1", "issue_prebatch_boundary_check_v1"]
