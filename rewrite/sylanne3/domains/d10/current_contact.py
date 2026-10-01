"""Current graph contact-policy projection; a candidate, never admission.

W01 supplies and verifies a complete fenced graph read. This helper consumes
only that read, so a restarted worker cannot silently drop durable claims.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import NamespaceId, QueryEpoch
from . import (
    ContactClaim, ContactContinuation, ContactPolicyCheck, LifeDomain,
    contact_policy_key, decode_contact_policy, decode_proactive_opportunity,
    opportunity_key,
)


@dataclass(frozen=True, slots=True)
class CurrentContactCandidateV1:
    status: str
    reasons: tuple[str, ...]
    check: ContactPolicyCheck | None
    graph_epoch: int | None
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch | None
    negative_predicates: tuple[str, ...]


def project_current_contact_v1(
    snapshot: GraphSnapshot, query: QueryEpoch, *, namespace: NamespaceId,
    policy_id: str, opportunity_id: str, now: float,
    continuation: ContactContinuation | None = None,
    audience: str | None = None,
) -> CurrentContactCandidateV1:
    """Evaluate consent, quiet, quota and unknown from durable graph heads."""
    if (type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(namespace) is not NamespaceId or type(policy_id) is not str
            or not policy_id or type(opportunity_id) is not str or not opportunity_id
            or type(now) not in (int, float) or not math.isfinite(now)
            or (continuation is not None and type(continuation) is not ContactContinuation)
            or (audience is not None and (type(audience) is not str or not audience))):
        raise TypeError("typed complete graph query and contact scope required")
    epoch = snapshot.epochs[0] if len(snapshot.epochs) == 1 else None
    graph_epoch = epoch.revision if epoch is not None else None
    predicates = ("d10.contact_policy:subject_channel_category:unique_current",
                  "d10.contact_claim:subject_channel_category:all_valid")
    def hold(reason: str, reads=()):
        return CurrentContactCandidateV1(
            "hold", (reason,), None, graph_epoch,
            tuple(sorted(set(reads), key=lambda v: v.key.token)),
            query if graph_epoch == query.revision else None, predicates)
    if (epoch is None or (epoch.bot, epoch.persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", epoch.revision)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        return hold("current_full_graph_query_unavailable")
    try:
        policy_atom = snapshot.get(contact_policy_key(namespace, policy_id))
        opportunity_atom = snapshot.get(opportunity_key(namespace, opportunity_id))
        if (policy_atom is None or opportunity_atom is None
                or not policy_atom.valid or not opportunity_atom.valid
                or policy_atom.revision < 1 or opportunity_atom.revision < 1):
            return hold("current_policy_or_opportunity_unavailable")
        policy = decode_contact_policy(policy_atom.value, namespace)
        opportunity = decode_proactive_opportunity(opportunity_atom.value, namespace)
        # D03's current route supplies the disclosure audience in production.
        # Keep the historical default for callers whose source is explicitly
        # granted to an entity; never manufacture an audience on the source.
        source_audience = opportunity.subject_ref if audience is None else audience
        reads = [GraphVersion(policy_atom.key, policy_atom.revision),
                 GraphVersion(opportunity_atom.key, opportunity_atom.revision)]
        if (policy.policy_id != policy_id
                or opportunity.opportunity_id != opportunity_id):
            return hold("current_policy_or_opportunity_version_changed", reads)
        source_key_ref = source_key(
            *namespace.as_tuple,
            AtomKey.from_token(opportunity.source_ref).owner.subject or "",
        )
        if source_key_ref.token != opportunity.source_ref:
            return hold("opportunity_source_unavailable", reads)
        source_atom = snapshot.get(source_key_ref)
        access_atom = snapshot.get(access_key(
            *namespace.as_tuple, source_key_ref.owner.subject or ""))
        if (source_atom is None or access_atom is None
                or not source_atom.valid or not access_atom.valid):
            return hold("opportunity_source_unavailable", reads)
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        reads.extend((GraphVersion(source_atom.key, source_atom.revision),
                      GraphVersion(access_atom.key, access_atom.revision)))
        if (source_atom.revision != opportunity_atom.value["source_revision"]
                or access_atom.revision != opportunity_atom.value["access_revision"]
                or source.source_id != source_key_ref.owner.subject
                or access_atom.value["source_id"] != source.source_id
                or access_atom.value["status"] != "active"
                or source_audience not in source.audiences
                or source_audience not in access_atom.value["audiences"]
                or "expression" not in source.purposes
                or "expression" not in access_atom.value["purposes"]):
            return hold("opportunity_source_changed", reads)
        policies = []
        claims = []
        for atom in snapshot.atoms:
            if (not atom.valid or atom.revision < 1
                    or atom.key.owner.kind != "persona"
                    or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple):
                continue
            if atom.key.type_name == "d10.contact_policy.v1":
                row = decode_contact_policy(atom.value, namespace)
                if (row.subject_ref, row.channel, row.category) == (
                    opportunity.subject_ref, opportunity.channel, opportunity.category):
                    policies.append(atom)
            elif atom.key.type_name in {"d10.contact_claim.v1", "d10.contact_claim.v2"}:
                value = atom.value
                from .contact_claim_v2 import decode_contact_claim_v2
                claim = decode_contact_claim_v2(value) if atom.key.type_name == "d10.contact_claim.v2" else ContactClaim(
                    value["contact_id"], value["communication_action_id"],
                    value["subject_ref"], value["channel"], value["category"],
                    tuple(value["segment_effects"]),
                    tuple(tuple(pair) for pair in value["observations"]),
                    value["status"], value["policy_id"], value["policy_version"],
                )
                if atom.key.name != claim.contact_id:
                    return hold("contact_claim_identity_changed", reads)
                if (claim.subject_ref, claim.channel, claim.category) == (
                    opportunity.subject_ref, opportunity.channel, opportunity.category):
                    claims.append(claim)
                    reads.append(GraphVersion(atom.key, atom.revision))
        if policies != [policy_atom]:
            return hold("unique_current_contact_policy_unavailable", reads)
        check = LifeDomain.contact_policy_check(
            policy, opportunity, tuple(claims), now=now,
            continuation=continuation)
        return CurrentContactCandidateV1(
            "policy_candidate" if check.result == "pass" else "hold",
            () if check.result == "pass" else check.reasons,
            check, graph_epoch,
            tuple(sorted(set(reads), key=lambda v: v.key.token)), query,
            predicates,
        )
    except (KeyError, TypeError, ValueError):
        return hold("current_contact_graph_unavailable")


__all__ = ["CurrentContactCandidateV1", "project_current_contact_v1"]
