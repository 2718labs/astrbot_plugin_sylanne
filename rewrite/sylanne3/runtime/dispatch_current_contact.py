"""Fenced D10 contact inventory and local rule recomputation for final dispatch."""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d08.execution import ActionIntent
from ..domains.d10 import (
    ContactClaim, ContactContinuation, ContactPolicyCheck, LifeDomain, contact_policy_key,
    decode_contact_policy, decode_proactive_opportunity, opportunity_key,
)
from ..graph_types import AtomKey, GraphSnapshot, owner_grant_key, validate_owner_grant_v1
from ..memory_types import SourceRecord, access_key, validate_access
from ..runtime_contracts import CheckReceipt, NamespaceId, QueryEpoch


_CONTACT_TYPES = (
    "d10.contact_policy.v1", "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2",
)


@dataclass(frozen=True)
class CurrentContactReadV1:
    namespace: NamespaceId
    query_epoch: QueryEpoch
    local_check: ContactPolicyCheck
    receipt: CheckReceipt
    policy_key: AtomKey
    opportunity_key: AtomKey
    claim_keys: tuple[AtomKey, ...]
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "owner_installation_approval_issuer_verification",
        "d06_source_correction_and_access_barrier",
        "w01_atomic_contact_adoption",
    )


def read_current_contact(
    db, namespace: NamespaceId, snapshot: GraphSnapshot, query: QueryEpoch,
    intent: ActionIntent, policy_id: str, opportunity_id: str, *, now: float,
    current_policy=None, scope=None, continuation: ContactContinuation | None = None,
) -> CurrentContactReadV1:
    """Verify the full contact namespace inventory under caller-held BEGIN IMMEDIATE.

    This checks durable graph rows, source/access and Owner-grant version pins.
    A passing provider receipt additionally requires the actual Authority policy
    read under this same live fence and a complete D06 correction query. It is
    an input to W01 admission; it never grants a contact claim or platform send.
    """
    if not db.in_transaction:
        raise ValueError("contact read requires the graph write transaction")
    if (type(namespace) is not NamespaceId or type(snapshot) is not GraphSnapshot
            or type(query) is not QueryEpoch or type(intent) is not ActionIntent):
        raise TypeError("typed namespace, snapshot, epoch and action are required")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or query != QueryEpoch(namespace, "all", snapshot.epochs[0].revision)):
        raise ValueError("contact read requires the full namespace query epoch")
    row = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                     namespace.as_tuple).fetchone()
    if (row[0] if row else 0) != query.revision:
        raise ValueError("contact graph epoch changed")

    atoms = tuple(atom for atom in snapshot.atoms if atom.valid and atom.key.type_name in _CONTACT_TYPES)
    by_token = {atom.key.token: atom for atom in atoms}
    if len(by_token) != len(atoms):
        raise ValueError("contact snapshot repeats a graph key")
    placeholders = ",".join("?" for _ in _CONTACT_TYPES)
    rows = db.execute(
        "SELECT token,revision,value,type_name FROM graph_atoms "
        f"WHERE bot=? AND persona=? AND type_name IN ({placeholders}) "
        "AND valid=1 ORDER BY token", namespace.as_tuple + _CONTACT_TYPES,
    ).fetchall()
    if len(rows) != len(atoms):
        raise ValueError("contact snapshot omits or invents a current row")
    policy_rows, opportunity_rows, claims = [], [], []
    claim_keys = []
    claim_spec = next(spec for spec in LifeDomain.type_specs()
                      if spec.name == "d10.contact_claim.v1")
    for token, revision, encoded, type_name in rows:
        atom = by_token.get(token)
        if (atom is None or atom.key != AtomKey.from_token(token)
                or atom.key.type_name != type_name or atom.revision != revision
                or atom.value != json.loads(encoded)
                or atom.key.owner.kind != "persona"
                or (atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple):
            raise ValueError("contact graph row changed")
        if type_name == "d10.contact_policy.v1":
            decoded = decode_contact_policy(atom.value, namespace)
            if atom.key != contact_policy_key(namespace, decoded.policy_id):
                raise ValueError("contact policy key or version changed")
            policy_rows.append((atom, decoded))
        elif type_name == "d10.proactive_opportunity.v1":
            decoded = decode_proactive_opportunity(atom.value, namespace)
            if atom.key != opportunity_key(namespace, decoded.opportunity_id):
                raise ValueError("opportunity key changed")
            opportunity_rows.append((atom, decoded))
        elif type_name == "d10.contact_claim.v2":
            from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2, contact_claim_key_v2
            decoded = decode_contact_claim_v2(atom.value)
            if atom.key != contact_claim_key_v2(namespace, decoded.contact_id):
                raise ValueError("contact claim key changed")
            claims.append(decoded)
            claim_keys.append(atom.key)
        else:
            claim_spec.validator(atom.value)
            data = atom.value
            decoded = ContactClaim(data["contact_id"], data["communication_action_id"],
                                   data["subject_ref"], data["channel"], data["category"],
                                   tuple(data["segment_effects"]),
                                   tuple(tuple(pair) for pair in data["observations"]),
                                   data["status"], data["policy_id"], data["policy_version"])
            if atom.key.name != decoded.contact_id:
                raise ValueError("contact claim key changed")
            claims.append(decoded)
            claim_keys.append(atom.key)
    selected_policy = [(atom, value) for atom, value in policy_rows if value.policy_id == policy_id]
    selected_opportunity = [(atom, value) for atom, value in opportunity_rows
                            if value.opportunity_id == opportunity_id]
    if len(selected_policy) != 1 or len(selected_opportunity) != 1:
        raise ValueError("selected contact policy or opportunity is absent")
    policy_atom, policy = selected_policy[0]
    opportunity_atom, opportunity = selected_opportunity[0]
    if (policy.subject_ref, policy.channel, policy.category) != (
            opportunity.subject_ref, opportunity.channel, opportunity.category):
        raise ValueError("policy and opportunity scope differ")

    def current_binding(ref: str, revision: int):
        key = AtomKey.from_token(ref)
        atom = snapshot.get(key)
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (ref, *namespace.as_tuple),
        ).fetchone()
        if (atom is None or not atom.valid or atom.revision != revision
                or row is None or row[0] != revision or row[2] != 1
                or atom.value != json.loads(row[1])):
            raise ValueError("contact binding is absent or stale")
        return key, atom.value

    grant_key = owner_grant_key(*namespace.as_tuple)
    _, grant = current_binding(grant_key.token, policy_atom.value["owner_grant_revision"])
    validate_owner_grant_v1(grant)
    if (grant["authority_id"] != policy_atom.value["approval_authority_id"]
            or grant["installation_id"] != policy_atom.value["installation_id"]):
        raise ValueError("policy approval authority differs from Owner grant")
    source_key, source_value = current_binding(
        opportunity.source_ref, opportunity_atom.value["source_revision"])
    if SourceRecord.from_dict(source_value).source_id != source_key.owner.subject:
        raise ValueError("opportunity source identity changed")
    access = access_key(*namespace.as_tuple, source_key.owner.subject)
    _, access_value = current_binding(access.token, opportunity_atom.value["access_revision"])
    validate_access(access_value)
    if access_value["source_id"] != source_key.owner.subject or access_value["status"] != "active":
        raise ValueError("opportunity source access is not active")

    scoped = tuple(claim for claim in claims if (
        claim.subject_ref, claim.channel, claim.category) == (
            opportunity.subject_ref, opportunity.channel, opportunity.category))
    check = LifeDomain.contact_policy_check(policy, opportunity, scoped, now=now,
                                          continuation=continuation)
    spec = tuple(item for item in intent.required_checks
                 if item.check_kind == "contact_policy" and item.provider_id == "d10.contact_policy")
    if len(spec) != 1 or spec[0].action_ref != intent.action_id:
        raise ValueError("action has no matching contact check")
    required = {item.ref: item.version for item in spec[0].required_input_versions}
    scope_ref = f"d10.contact_policy:{opportunity.subject_ref}:{opportunity.channel}:{opportunity.category}"
    selected_refs = {policy_id: policy_atom.revision, opportunity_id: opportunity_atom.revision,
                     scope_ref: query.revision}
    selected_refs.update({claim.contact_id: atom.revision for claim, atom in zip(claims, (
        by_token[key.token] for key in claim_keys)) if claim in scoped})
    if (len(required) != len(spec[0].required_input_versions)
            or set(required) != set(selected_refs) | {spec[0].criteria_version}
            or any(required.get(ref) != version for ref, version in selected_refs.items())):
        raise ValueError("contact check lacks exact current input coverage")
    current_binding(spec[0].criteria_version, required[spec[0].criteria_version])
    if (intent.target_ref != opportunity.subject_ref
            or spec[0].subject_ref != f"persona:{namespace.persona_id}"
            or spec[0].purpose != intent.purpose):
        raise ValueError("contact action scope changed")
    missing = []
    if current_policy is None:
        missing.append("owner_installation_approval_issuer_verification")
    else:
        from .d10_contact_policy_authority_v1 import require_current_contact_policy_v1
        require_current_contact_policy_v1(current_policy, scope, policy_atom.value, now=now)
    from .dispatch_source_correction_barrier import read_source_correction_barrier
    correction = read_source_correction_barrier(db, namespace, query,
        tuple(dict.fromkeys((opportunity.source_ref, *intent.source_refs))),
        dependent_ref=intent.action_id)
    missing.extend(correction.missing_sources)
    receipt = CheckReceipt(spec[0].check_kind, spec[0].subject_ref, spec[0].action_ref,
                           spec[0].purpose, spec[0].required_input_versions, "full",
                           "unknown" if missing else check.result,
                           check.valid_until, spec[0].provider_id)
    scoped_keys = tuple(key for key, claim in zip(claim_keys, claims) if claim in scoped)
    return CurrentContactReadV1(namespace, QueryEpoch(namespace, scope_ref, query.revision),
                                check, receipt, policy_atom.key, opportunity_atom.key,
                                scoped_keys,
                                "check_pass" if not missing and check.result == "pass" else "hold",
                                tuple(dict.fromkeys(missing)))
