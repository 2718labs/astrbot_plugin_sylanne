"""Read the policy actually adopted for D07 from one current graph transaction."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import sqlite3

from ..domains.d07 import AttentionPolicy
from ..domains.d12.types import ActiveSchemeHeadV1, active_scheme_head_key
from ..graph_types import GraphVersion
from ..runtime_contracts import NamespaceId, canonical_serialize
from .d12_compiled_candidate_store_v1 import verify_d12_domain_candidate_v1
from .d12_domain_scheme_compile_v1 import (
    ATTENTION_POLICY_FIELD, D12AttentionPolicyCandidateV1,
)
from .scheme_original_store_v1 import read_compilation_original_for_operation_v1


@dataclass(frozen=True, slots=True)
class D12CurrentD07PolicyReadV1:
    policy: AttentionPolicy
    active_head_ref: GraphVersion
    compiled_digest: str | None
    candidate_digest: str | None


def read_current_d07_attention_policy_v1(
    db: sqlite3.Connection, namespace: NamespaceId,
) -> D12CurrentD07PolicyReadV1:
    """Resolve the initial default or exact immutable active D07 candidate."""
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("current D07 policy requires graph transaction")
    from .d12_current_domain_selection_v1 import read_current_domain_selection_v1
    version, compiled, receipt = read_current_domain_selection_v1(
        db, namespace, domain="d07", field_name=ATTENTION_POLICY_FIELD)
    if receipt is None:
        return D12CurrentD07PolicyReadV1(AttentionPolicy.default(), version, None, None)
    candidate_row = db.execute(
        "SELECT domain,field_input_digest,proposal_schema_hash,candidate_digest,"
        "candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 "
        "WHERE bot=? AND persona=? AND candidate_ref=?",
        (*namespace.as_tuple, receipt.candidate_ref),
    ).fetchone()
    if candidate_row is None or sha256(candidate_row[4].encode()).hexdigest() != candidate_row[5]:
        raise ValueError("adopted D07 candidate original is absent or changed")
    try:
        raw = json.loads(candidate_row[4])
        if (type(raw) is not dict
                or raw.pop("$type", None) != (
                    "sylanne3.runtime.d12_domain_scheme_compile_v1."
                    "D12AttentionPolicyCandidateV1")
                or set(raw) != {
                "namespace", "domain", "field_names", "field_input_digest",
                "proposal_schema_hash", "policy", "candidate_digest", "status"}):
            raise ValueError("D07 candidate fields differ")
        namespace_value = raw["namespace"]
        policy_value = raw["policy"]
        if (type(namespace_value) is not dict
                or namespace_value.pop("$type", None) !=
                   "sylanne3.runtime_contracts.NamespaceId"
                or type(policy_value) is not dict
                or policy_value.pop("$type", None) !=
                   "sylanne3.domains.d07.AttentionPolicy"):
            raise ValueError("D07 candidate type tags differ")
        candidate = D12AttentionPolicyCandidateV1(
            NamespaceId(**namespace_value), raw["domain"],
            tuple(raw["field_names"]), raw["field_input_digest"],
            raw["proposal_schema_hash"], AttentionPolicy(**policy_value),
            raw["candidate_digest"], raw["status"],
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError("adopted D07 candidate is malformed") from exc
    if (candidate.namespace != namespace
            or candidate_row[4] != canonical_serialize(candidate)
            or not verify_d12_domain_candidate_v1(
                db, namespace, candidate, receipt)):
        raise ValueError("adopted D07 candidate proof differs")
    return D12CurrentD07PolicyReadV1(
        candidate.policy, version, compiled.compiled_digest,
        candidate.candidate_digest)


__all__ = (
    "D12CurrentD07PolicyReadV1", "read_current_d07_attention_policy_v1",
)
