"""Resolve the active D09 expression policy within a graph transaction."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import sqlite3

from ..domains.d09.expression_policy import D09ExpressionPolicyV1
from ..domains.d12.types import ActiveSchemeHeadV1, active_scheme_head_key
from ..graph_types import GraphVersion
from ..runtime_contracts import NamespaceId, canonical_serialize
from .d12_compiled_candidate_store_v1 import verify_d12_domain_candidate_v1
from .d12_domain_scheme_compile_v1 import (
    D12ExpressionPolicyCandidateV1, EXPRESSION_POLICY_FIELD,
)
from .scheme_original_store_v1 import read_compilation_original_for_operation_v1


@dataclass(frozen=True, slots=True)
class D12CurrentD09PolicyReadV1:
    policy: D09ExpressionPolicyV1 | None
    active_head_ref: GraphVersion
    compiled_digest: str | None
    candidate_digest: str | None


def read_current_d09_expression_policy_v1(
    db: sqlite3.Connection, namespace: NamespaceId,
) -> D12CurrentD09PolicyReadV1:
    """Read a persisted adopted policy; absent/initial uses D09's default."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("current D09 policy requires graph transaction")
    from .d12_current_domain_selection_v1 import read_current_domain_selection_v1
    version, compiled, receipt = read_current_domain_selection_v1(
        db, namespace, domain="d09", field_name=EXPRESSION_POLICY_FIELD)
    if receipt is None:
        return D12CurrentD09PolicyReadV1(None, version, None, None)
    candidate_row = db.execute(
        "SELECT domain,field_input_digest,proposal_schema_hash,candidate_digest,"
        "candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 "
        "WHERE bot=? AND persona=? AND candidate_ref=?",
        (*namespace.as_tuple, receipt.candidate_ref),
    ).fetchone()
    if (candidate_row is None
            or sha256(candidate_row[4].encode()).hexdigest() != candidate_row[5]):
        raise ValueError("adopted D09 candidate original is absent or changed")
    try:
        raw = json.loads(candidate_row[4])
        if (type(raw) is not dict
                or raw.pop("$type", None) != (
                    "sylanne3.runtime.d12_domain_scheme_compile_v1."
                    "D12ExpressionPolicyCandidateV1")
                or set(raw) != {
                "namespace", "domain", "field_names", "field_input_digest",
                "proposal_schema_hash", "policy", "candidate_digest", "status"}):
            raise ValueError("D09 candidate fields differ")
        namespace_value = raw["namespace"]
        policy_value = raw["policy"]
        if (type(namespace_value) is not dict
                or namespace_value.pop("$type", None) !=
                   "sylanne3.runtime_contracts.NamespaceId"
                or type(policy_value) is not dict
                or policy_value.pop("$type", None) !=
                   "sylanne3.domains.d09.expression_policy.D09ExpressionPolicyV1"):
            raise ValueError("D09 candidate type tags differ")
        candidate = D12ExpressionPolicyCandidateV1(
            NamespaceId(**namespace_value), raw["domain"],
            tuple(raw["field_names"]), raw["field_input_digest"],
            raw["proposal_schema_hash"], D09ExpressionPolicyV1(**policy_value),
            raw["candidate_digest"], raw["status"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("adopted D09 candidate is malformed") from exc
    if (candidate.namespace != namespace
            or candidate_row[4] != canonical_serialize(candidate)
            or not verify_d12_domain_candidate_v1(
                db, namespace, candidate, receipt)):
        raise ValueError("adopted D09 candidate proof differs")
    return D12CurrentD09PolicyReadV1(
        candidate.policy, version, compiled.compiled_digest,
        candidate.candidate_digest,
    )


__all__ = (
    "D12CurrentD09PolicyReadV1", "read_current_d09_expression_policy_v1",
)
