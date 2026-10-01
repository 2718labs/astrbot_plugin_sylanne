"""One-snapshot C04 and association write-before-adoption check.

W01 supplies one current graph snapshot and original D07/D02/D11 proposals.
This pure function assembles a candidate bundle and checks every association
read against that snapshot. It cannot attest that the earlier traversal ran
inside W01's SQLite transaction or issue resource/Authority receipts.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion
from ...memory_types import SourceRecord, access_key, validate_access, validate_association
from ...runtime_contracts import CommandEnvelope, DomainBundle, DomainProposal, NamespaceId
from ...runtime.d11_types import D11RuntimeProvider
from ..d02 import BodyDomain
from ..d04 import AffectCoupling, AffectProvider, AffectScheme
from ..d07 import D07DomainProvider
from . import CandidateSet, SelectionTicket, source_correction_head_key
from .current_association_candidates import CurrentAssociationCandidatesV1
from .current_c04_bundle import assemble_current_c04_bundle_v1
from .current_focus_binding import bind_current_c04_focus_v1
from .current_recollection_bridge import CurrentC04SourceCandidateV1


@dataclass(frozen=True, slots=True)
class CurrentC04AssemblyOriginalsV1:
    mood_key: AtomKey
    scheme: AffectScheme
    coupling: AffectCoupling
    affect_provider: AffectProvider
    experience_id: str
    supporting_proposals: tuple[DomainProposal, ...]
    choice_ref: str
    d02_settlement_ref: str
    d11_cost_settlement_ref: str
    persistent_job_ref: str
    outbox_ref: str


@dataclass(frozen=True, slots=True)
class CurrentC04AssociationPreflightV1:
    bundle_candidate: DomainBundle
    association_candidates: CurrentAssociationCandidatesV1
    read_versions: tuple[GraphVersion, ...]
    status: str = "candidate_hold_w01_atomic_commit_and_same_transaction_traversal"


def _bind_support_originals(originals: CurrentC04AssemblyOriginalsV1,
                            envelope: CommandEnvelope, namespace: NamespaceId,
                            candidate: CurrentC04SourceCandidateV1,
                            ticket: SelectionTicket,
                            current_snapshot: GraphSnapshot) -> None:
    """Bind domain-owned originals; W01 separately verifies issuer receipts."""
    activity = envelope.identity.activity_id
    operation = envelope.identity.operation_id
    by_domain = {item.domain: item for item in originals.supporting_proposals}
    expected = {
        originals.choice_ref: ("d07", "d07.selection_ticket.v1"),
        originals.d02_settlement_ref: ("d02", "d02.settlement.v1"),
        originals.d11_cost_settlement_ref: ("d11", "runtime.cost_settlement"),
        originals.persistent_job_ref: ("d11", "runtime.job"),
        originals.outbox_ref: ("d11", "runtime.outbox"),
    }
    if len(expected) != 5:
        raise ValueError("C04 support refs are not distinct")
    writes = {}
    for domain, proposal in by_domain.items():
        for write in proposal.typed_writes:
            if write.key.token in expected:
                if write.key.token in writes:
                    raise ValueError("C04 support original is duplicated")
                writes[write.key.token] = (domain, write)
    if set(writes) != set(expected):
        raise ValueError("C04 support original is absent")
    d07_proposal = by_domain["d07"]
    d02_proposal = by_domain["d02"]
    d11_proposal = by_domain["d11"]
    if (len(d07_proposal.typed_writes) != 2
            or len(d02_proposal.typed_writes) != 3
            or len(d11_proposal.typed_writes) != 3):
        raise ValueError("C04 support proposal has unexpected persistent originals")
    for ref, (expected_domain, type_name) in expected.items():
        domain, write = writes[ref]
        key = AtomKey.from_token(ref)
        if (domain != expected_domain or key.type_name != type_name
                or key.owner.kind != "activity" or key.owner.subject != activity
                or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
            raise ValueError("C04 support original crosses operation or domain")
    choice = writes[originals.choice_ref][1]
    interpretation_refs = candidate.proposal.now_interpretation_refs
    interpretation_writes = tuple(write for write in d07_proposal.typed_writes
                                  if write.key.type_name == "d07.current_interpretation.v1")
    if (choice.key.name != ticket.ticket_id
            or choice.value != {
                "schema": "d07.selection_ticket.v1",
                "ticket_id": ticket.ticket_id,
                "activity_id": ticket.activity_id,
                "candidate_set_id": ticket.candidate_set_id,
                "selected_candidate_ids": list(ticket.selected_candidate_ids),
                "focus_epoch": ticket.focus_epoch,
            }
            or len(interpretation_refs) != 1
            or len(interpretation_writes) != 1
            or interpretation_writes[0].key.token != interpretation_refs[0]
            or interpretation_writes[0].key.owner.subject != activity
            or tuple(interpretation_writes[0].value.get("source_refs", ()))
               != (candidate.reconstruction.source_ref,)):
        raise ValueError("C04 D07 choice or current interpretation differs from selection")
    D07DomainProvider().validate(d07_proposal)
    d02_writes = {write.key.type_name: write for write in d02_proposal.typed_writes}
    if set(d02_writes) != {
            "d02.body_state.v1", "d02.reservation.v1", "d02.settlement.v1"}:
        raise ValueError("C04 D02 requires exact state, reservation and settlement")
    state_write = d02_writes["d02.body_state.v1"]
    reservation_write = d02_writes["d02.reservation.v1"]
    settlement_write = d02_writes["d02.settlement.v1"]
    d02 = settlement_write.value
    state = state_write.value
    reservation = reservation_write.value
    old_state = current_snapshot.get(state_write.key)
    old_reservation = current_snapshot.get(reservation_write.key)
    guarded = {version.key: version.revision
               for version in envelope.version_guard.read_versions}
    if (state_write.key.owner.kind != "persona"
            or state_write.key.owner.subject is not None
            or (state_write.key.owner.bot, state_write.key.owner.persona)
               != namespace.as_tuple
            or reservation_write.key.owner.kind != "activity"
            or reservation_write.key.owner.subject != activity
            or (reservation_write.key.owner.bot,
                reservation_write.key.owner.persona) != namespace.as_tuple
            or settlement_write.key.token != originals.d02_settlement_ref
            or old_state is None or not old_state.valid
            or old_reservation is None or not old_reservation.valid
            or guarded.get(state_write.key) != old_state.revision
            or guarded.get(reservation_write.key) != old_reservation.revision
            or state.get("profile_id") != state_write.key.name
            or state.get("version") != old_state.revision + 1
            or reservation.get("reservation_id") != reservation_write.key.name
            or reservation.get("status") != "settled"
            or old_reservation.value.get("status") != "reserved"
            or old_reservation.value.get("reservation_id")
               != reservation_write.key.name
            or old_reservation.value.get("quote_id") != reservation.get("quote_id")
            or old_reservation.value.get("effect_id") != reservation.get("effect_id")
            or d02.get("state") != state
            or d02.get("reservation") != reservation
            or d02.get("duplicate") is not False
            or d02.get("overrun") != 0
            or d02.get("unpaid_cost") != 0
            or not envelope.version_guard.resource_lease_versions):
        raise ValueError("C04 D02 settlement state, reservation or guard differs")
    BodyDomain().validate(d02_proposal)
    cost = writes[originals.d11_cost_settlement_ref][1].value
    job = writes[originals.persistent_job_ref][1].value
    outbox = writes[originals.outbox_ref][1].value
    for row in (cost, job, outbox):
        if (row.get("bot_id"), row.get("persona_id"), row.get("activity_id")) != (
                *namespace.as_tuple, activity):
            raise ValueError("C04 D11 original crosses activity")
    if (cost.get("bundle_operation_id") != operation
            or cost.get("cost_operation_id") != operation
            or cost.get("budget_operation_id") != operation
            or cost.get("status") != "settled"
            or cost.get("budget_phase") != "settle"
            or not cost.get("budget_receipt_digest")
            or job.get("operation_id") != operation
            or outbox.get("operation_id") != operation
            or outbox.get("job_ref") != originals.persistent_job_ref
            or outbox.get("job_id") != job.get("job_id")
            or outbox.get("idempotency_key") != f"d06:c04:{activity}"):
        raise ValueError("C04 D11 cost, job, and outbox originals differ")
    if (cost.get("lease_id") != job.get("parent_budget_lease_ref")
            or job.get("job_id") != AtomKey.from_token(originals.persistent_job_ref).name
            or outbox.get("payload_ref") != candidate.proposal.recollection_id
            or outbox.get("phase") != "pending"):
        raise ValueError("C04 D11 original is not bound to this recollection and lease")
    D11RuntimeProvider().validate(d11_proposal, None)


def preflight_current_c04_association_v1(
    candidate: CurrentC04SourceCandidateV1, *, ticket: SelectionTicket,
    candidates: CandidateSet, associations: CurrentAssociationCandidatesV1,
    current_snapshot: GraphSnapshot, namespace: NamespaceId,
    envelope: CommandEnvelope, originals: CurrentC04AssemblyOriginalsV1,
    now: float, audience: str, purpose: str,
) -> CurrentC04AssociationPreflightV1:
    """Check C04 and association inputs against the same W01 supplied heads."""
    if (type(candidate) is not CurrentC04SourceCandidateV1
            or type(associations) is not CurrentAssociationCandidatesV1
            or type(current_snapshot) is not GraphSnapshot
            or type(namespace) is not NamespaceId
            or type(envelope) is not CommandEnvelope
            or type(originals) is not CurrentC04AssemblyOriginalsV1
            or type(now) not in (int, float) or not math.isfinite(now)):
        raise TypeError("typed current C04, association, snapshot, and originals required")
    if (current_snapshot.epochs != (candidate.graph_epoch,)
            or associations.graph_epoch != candidate.graph_epoch
            or envelope.authority.namespace != namespace
            or (candidate.graph_epoch.bot, candidate.graph_epoch.persona) != namespace.as_tuple
            or associations.status != "candidate_hold_d07_choice_w01_fence"
            or associations.cue_source_ref != candidate.reconstruction.source_ref
            or len(current_snapshot.atoms) > 4096
            or len({atom.key for atom in current_snapshot.atoms}) != len(current_snapshot.atoms)
            or {item.domain for item in originals.supporting_proposals} != {"d07", "d02", "d11"}
            or len(originals.supporting_proposals) != 3
            or any(item.envelope != envelope for item in originals.supporting_proposals)):
        raise ValueError("C04 association epoch, support originals, or scope differ")
    _bind_support_originals(originals, envelope, namespace, candidate, ticket,
                            current_snapshot)
    focused = bind_current_c04_focus_v1(
        candidate, ticket=ticket, focus_snapshot=current_snapshot,
        namespace=namespace, now=now, audience=audience, purpose=purpose,
    )
    required = {version.key: version for version in (
        *focused.read_versions, *associations.read_versions,
    )}
    if (len(required) != len(set(focused.read_versions + associations.read_versions))
            and any(required[version.key] != version for version in
                    (*focused.read_versions, *associations.read_versions))):
        raise ValueError("C04 and association read revisions conflict")
    if (not set(required.values()) <= set(current_snapshot.versions)
            or not set(required.values()) <= set(envelope.version_guard.read_versions)):
        raise ValueError("W01 snapshot or envelope lacks current association closure")
    # Every source encountered by the traversal is rechecked, including edge
    # bases and targets. The absent correction head is a required guarded read.
    source_keys = {version.key for version in associations.read_versions
                   if version.key.type_name == "memory.source"}
    source_keys.add(AtomKey.from_token(associations.cue_source_ref))
    edge_targets: set[str] = set()
    for ref in associations.edge_refs:
        key = AtomKey.from_token(ref)
        atom = current_snapshot.get(key)
        if (key.type_name != "memory.association.v1" or atom is None
                or not atom.valid or atom.revision < 1
                or GraphVersion(key, atom.revision) not in required.values()):
            raise ValueError("association edge is not a guarded current original")
        validate_association(atom.value)
        for field in ("source_ref", "target_ref"):
            source_keys.add(AtomKey.from_token(atom.value[field]))
        source_keys.update(AtomKey.from_token(ref)
                           for ref in atom.value["basis_source_refs"])
        edge_targets.add(atom.value["target_ref"])
    if any(item.source_ref not in edge_targets
           or item.evidence_eligibility != "subjective_association_only"
           for item in associations.candidates):
        raise ValueError("association candidate lacks a guarded personal edge")
    for source in source_keys:
        if (source.type_name != "memory.source"
                or (source.owner.bot, source.owner.persona) != namespace.as_tuple):
            raise ValueError("association source crosses namespace")
        access = access_key(*namespace.as_tuple, source.owner.subject)
        head = source_correction_head_key(namespace, source.owner.subject)
        source_atom, access_atom, head_atom = (
            current_snapshot.get(key) for key in (source, access, head)
        )
        if (source_atom is None or not source_atom.valid or source_atom.revision < 1
                or access_atom is None or not access_atom.valid or access_atom.revision < 1
                or head_atom is None or head_atom.valid or head_atom.revision != 0
                or any(GraphVersion(key, atom.revision) not in envelope.version_guard.read_versions
                       for key, atom in ((source, source_atom), (access, access_atom),
                                         (head, head_atom)))):
            raise ValueError("association source/access/correction closure is incomplete")
        for key, atom in ((source, source_atom), (access, access_atom),
                          (head, head_atom)):
            current_version = GraphVersion(key, atom.revision)
            if key in required and required[key] != current_version:
                raise ValueError("association source read revision differs")
            required[key] = current_version
        record = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        if (record.source_id != source.owner.subject
                or access_atom.value["source_id"] != record.source_id
                or access_atom.value["status"] != "active"
                or audience not in record.audiences
                or audience not in access_atom.value["audiences"]
                or purpose not in record.purposes
                or purpose not in access_atom.value["purposes"]):
            raise PermissionError("association source is not currently available")
    bundle = assemble_current_c04_bundle_v1(
        focused, envelope=envelope, ticket=ticket, candidates=candidates,
        mood_snapshot=current_snapshot, mood_key=originals.mood_key,
        scheme=originals.scheme, coupling=originals.coupling,
        affect_provider=originals.affect_provider,
        experience_id=originals.experience_id,
        supporting_proposals=originals.supporting_proposals,
        choice_ref=originals.choice_ref,
        d02_settlement_ref=originals.d02_settlement_ref,
        d11_cost_settlement_ref=originals.d11_cost_settlement_ref,
        persistent_job_ref=originals.persistent_job_ref,
        outbox_ref=originals.outbox_ref,
    )
    if any(write.key.type_name in {"memory.source", "memory.association.v1",
                                   "d03.world_event"}
           for proposal in bundle.proposals for write in proposal.typed_writes):
        raise ValueError("C04 association preflight cannot create external facts or edges")
    return CurrentC04AssociationPreflightV1(
        bundle, associations,
        tuple(required[key] for key in sorted(required, key=lambda item: item.token)),
    )


__all__ = ["CurrentC04AssemblyOriginalsV1", "CurrentC04AssociationPreflightV1",
           "preflight_current_c04_association_v1"]
