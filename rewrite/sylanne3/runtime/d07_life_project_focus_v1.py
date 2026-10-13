"""D07's finite, explicit Owner choice of an internal project focus."""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d02 import BodyDomain
from ..domains.d07 import AttentionTicket, D07DomainProvider, FocusState, attention_ticket_key
from ..domains.d12.types import active_scheme_head_key
from ..graph_types import AtomKey, Owner
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import canonical_digest
from .budget import get_budget_lease, require_budget_family_admissible
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d08_life_admission_v1 import _adopted
from .d11_life_contract_v1 import WORK_KIND
from .d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1


@dataclass(frozen=True, slots=True)
class FocusLifeProjectRequestV1:
    project_ref: str
    source_ref: str
    cpu_ceiling_ms: int
    valid_for_seconds: int

    def __post_init__(self):
        if (AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1"
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.valid_for_seconds) is not int or not 1 <= self.valid_for_seconds <= 600):
            raise ValueError("Owner project focus requires actual locators and finite resource/time intent")


class InstalledD07LifeFocusReadersV1:
    def __init__(self, *, issuer, body_readers):
        from .issuers import D11BudgetJobIssuer
        from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
        if type(issuer) is not D11BudgetJobIssuer or type(body_readers) is not InstalledD02ProductionReadersV1:
            raise TypeError("D07 project focus requires the actual current Body and D11 readers")
        self.issuer, self.body_readers = issuer, body_readers


def _keys(namespace, operation_id):
    tag = canonical_digest((namespace, operation_id))[:48]
    return (attention_ticket_key(namespace, "attention:owner-project:" + tag),
        AtomKey(Owner("persona", *namespace.as_tuple), "d07.focus.v1", namespace.persona_id))


def read_plan_life_project_focus_v1(db, *, namespace, operation_id, request):
    from ..domains.d06 import source_correction_head_key
    keys = [AtomKey.from_token(request.project_ref), active_scheme_head_key(namespace), *_keys(namespace, operation_id)]
    rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d07.attention_ticket.v1' "
        "AND valid=1 ORDER BY token LIMIT 129", namespace.as_tuple).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("complete_owner_focus_ticket_inventory")
    # Existing tickets stay separate evidence roots. Their Source closures are
    # exact current reads for auxiliary selection, not provenance of the new
    # project's ticket, whose qualification is only its requested Source.
    pending = [ref for (value,) in rows for ref in json.loads(value)["source_refs"]]
    seen = set()
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= 128:
            raise MissingProductionOriginalV1("bounded_owner_focus_source_inventory")
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject or ""):
            raise ValueError("Owner focus ticket Source crossed its current namespace")
        seen.add(ref)
        keys.extend((key, access_key(*namespace.as_tuple, key.owner.subject), source_correction_head_key(namespace, key.owner.subject)))
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
        if row is not None and row[1] == 1:
            source = SourceRecord.from_dict(json.loads(row[0]))
            pending.extend(source_key(*namespace.as_tuple, parent).token for parent in source.parent_source_ids)
    return production_read_plan_v1(("d07.attention_ticket.v1", "d02.body_profile.v1", "d02.body_state.v1", "d02.reservation.v1"),
        keys, (request.source_ref,), (request.project_ref,))


def stage_focus_life_project_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD07LifeFocusReadersV1:
        raise TypeError("exact installed D07 project focus readers required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    project = read.head(db, request.project_ref, required=True)
    _adopted(db, read, project)
    if project.value["reality"] != "real_execution" or project.value["next_step"] != "source_note":
        raise MissingProductionOriginalV1("actual_owner_source_note_project")
    for audience in frame.envelope.authority.audience:
        for purpose in ("context", "consolidation"):
            read.source_family(db, (request.source_ref,), purpose=purpose, audience=audience)
    policies = db.execute("SELECT policy_id,version FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? "
        "AND status='active' AND json_extract(policy_json,'$.work_kind')=? ORDER BY policy_id,version LIMIT 2",
        (*ns.as_tuple, WORK_KIND)).fetchall()
    if len(policies) != 1:
        raise MissingProductionOriginalV1("unique_installed_source_note_focus_policy")
    policy_id, policy_version = policies[0]
    price = installed_readers.body_readers.body_quote_authority.policy(db, ns, policy_id, policy_version)
    profile, body, reservations = installed_readers.body_readers._current_body(db, read, price.profile.profile_id)
    if (price.work_kind != WORK_KIND or price.profile != profile
            or BodyDomain().check_work_start(body, reservations,
                additional_cost=price.component.fixed_cost).status != "clear"):
        raise MissingProductionOriginalV1("actual_project_focus_body_resources")
    budget_ref = frame.envelope.parent_budget_lease_ref
    budget = get_budget_lease(db, budget_ref)
    grant = installed_readers.issuer.current_budget_grant(db, budget_ref)
    require_budget_family_admissible(db, budget_ref)
    remaining = budget.limits.get("thread_cpu_ms", 0) - sum(values.get("thread_cpu_ms", 0)
        for values in (budget.used, budget.reserved, budget.unconfirmed))
    if (budget.state != "active" or (budget.bot_id, budget.persona_id) != ns.as_tuple
            or (grant.bot_id, grant.persona_id, grant.lease_id) != (*ns.as_tuple, budget_ref)
            or WORK_KIND not in grant.allowed_work_kinds or grant.valid_until_utc <= frame.now_utc
            or request.cpu_ceiling_ms > min(remaining, grant.max_ceiling.get("thread_cpu_ms", 0))):
        raise MissingProductionOriginalV1("actual_project_focus_cpu_authorization")
    policy = read_current_d07_attention_policy_v1(db, ns)
    if policy.active_head_ref not in frame.snapshot.versions:
        raise ValueError("Owner focus policy head is outside its actual current read set")
    existing = []
    for atom in read.complete_inventory(db, "d07.attention_ticket.v1"):
        if not atom.valid:
            continue
        _adopted(db, read, atom)
        value = {k: v for k, v in atom.value.items() if k != "schema"}
        value["source_refs"], value["cancel_refs"] = tuple(value["source_refs"]), tuple(value["cancel_refs"])
        ticket = AttentionTicket(**value)
        if ticket.valid_until <= frame.now_utc or not ticket.eligible or not ticket.resources_available:
            continue
        if ticket.category == "required":
            raise MissingProductionOriginalV1("actual_required_attention_must_finish_or_expire:" + atom.key.token)
        if ticket.cancel_refs:
            # Cancellation requires its own genuine current completion path;
            # it never turns an unresolved ticket into a selected auxiliary.
            continue
        try:
            for audience in frame.envelope.authority.audience:
                for purpose in ("context", "consolidation"):
                    read.source_family(db, ticket.source_refs, purpose=purpose, audience=audience)
        except MissingProductionOriginalV1:
            continue
        existing.append((atom.key.token, ticket))
    ticket_key, focus_key = _keys(ns, frame.envelope.identity.operation_id)
    if read.head(db, ticket_key).revision:
        raise ValueError("Owner focus operation already has an adopted ticket")
    prior = read.head(db, focus_key)
    if prior.revision:
        _adopted(db, read, prior)
        current = FocusState(**{**{k: v for k, v in prior.value.items() if k != "schema"},
            "auxiliary_ticket_refs": tuple(prior.value["auxiliary_ticket_refs"])})
    else:
        current = FocusState(ns.persona_id, 0, None, (), "no_eligible_ticket")
    # Explicit Owner choice replaces only automatic non-required primary
    # scoring. It does not fabricate urgency or complete the old dialogue.
    ranked = D07DomainProvider.rank_attention(tuple(ticket for _, ticket in existing), policy.policy, now=frame.now_utc)
    refs = {ticket.ticket_id: ref for ref, ticket in existing}
    auxiliary = tuple(refs[item.ticket.ticket_id] for item in ranked[:policy.policy.auxiliary_limit])
    ticket = AttentionTicket(ticket_key.name, "project:" + request.project_ref, request.project_ref, request.source_ref,
        "background", 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, body.fatigue[WORK_KIND], 0.0,
        frame.snapshot.epochs[0].revision, min(frame.now_utc + request.valid_for_seconds, grant.valid_until_utc), True, True, (),
        frame.envelope.source_qualification.source_refs)
    focus = FocusState(ns.persona_id, current.focus_epoch + 1, ticket_key.token, auxiliary, "owner_directed_project")
    provider = D07DomainProvider()
    proposal = provider.attention_focus_proposal(frame.envelope, frame.snapshot, ticket, focus, now=frame.now_utc)
    stage = stage_result_v1(frame, "d07", "focus_life_project", request, writes=proposal.typed_writes,
        provenance={"owner_project_ref": request.project_ref, "owner_project_source_ref": request.source_ref,
            "owner_focus_selection": "owner_directed_project"},
        proposal_schema="d07.proposal.v1", proposal_hash=provider.descriptor.request_schema_hash)
    # stage_result carries invalidation dependencies by default. D07's fixed
    # focus contract instead records exactly its real Source provenance.
    from dataclasses import replace
    stage = replace(stage, proposals=(replace(stage.proposals[0], dependencies=proposal.dependencies),))
    provider.validate(stage.proposals[0], frame.snapshot)
    return stage
