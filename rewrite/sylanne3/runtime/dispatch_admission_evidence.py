"""Transaction-bound facts for a future D11 dispatch admission issuer.

This reader checks business graph and ledger state.  It cannot issue an
admission: D01 authority, the D08 execution/cancellation read, the independent
execution journal, and the concrete platform command still need their own
current, fenced proofs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math

from ..domains.d06 import D06DomainProvider, SourceGrantRead
from ..domains.d08 import GoalExecutionProvider
from ..domains.d09 import D09ExpressionProvider
from ..graph_types import GraphSnapshot
from ..runtime_contracts import DomainBundle, QueryEpoch, canonical_digest
from .budget import BudgetLease, get_budget_lease
from .dispatch_candidate import (
    DispatchCandidateEvidenceV1, validate_dispatch_candidate_writes,
)
from .dispatch_current_commitments import (
    CurrentD08ConflictFactsV1, read_current_d08_conflict_facts,
)
from .dispatch_current_projection import (
    CurrentDispatchProjectionV1, read_current_dispatch_projection,
)


@dataclass(frozen=True)
class CurrentAdmissionFactsV1:
    """Verified local facts; ``status`` never authorizes admission or send."""

    candidate_digest: str
    source_check_digest: str
    projection: CurrentDispatchProjectionV1
    d08_graph_facts: CurrentD08ConflictFactsV1
    budget_lease: BudgetLease
    reservation_digest: str
    budget_ceiling: dict[str, int]
    status: str = "hold"
    missing_sources: tuple[str, ...] = (
        "d01.current_owner_and_role",
        "d03_d05.required_check_receipts",
        "d08.atomic_execution_and_cancellation",
        "d11.signed_grant_and_journal_fence",
        "dispatch.command_route_and_clock",
    )


def read_current_admission_facts(
    db, bundle: DomainBundle, snapshot: GraphSnapshot,
    candidate: DispatchCandidateEvidenceV1, *, now_utc: float,
) -> CurrentAdmissionFactsV1:
    """Re-read a staged D08/D09 candidate before graph writes are applied.

    The caller must retain the graph transaction and its Authority fence.
    The coordinator's receipt hook runs after graph writes and cannot pass its
    old guard snapshot here.  This only returns facts that it can independently
    compare to SQLite; no caller-supplied check receipt promotes it to READY.
    """
    if not db.in_transaction:
        raise ValueError("dispatch facts require a held graph transaction")
    if (type(bundle) is not DomainBundle or type(snapshot) is not GraphSnapshot
            or type(candidate) is not DispatchCandidateEvidenceV1
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ValueError("typed dispatch candidate and finite time required")
    envelope = bundle.envelope
    namespace = envelope.authority.namespace
    query = QueryEpoch(namespace, "all", candidate.query_epoch)
    if (candidate.status != "source_qualified" or len(snapshot.epochs) != 1
            or query.revision != snapshot.epochs[0].revision
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona)
            != namespace.as_tuple
            or envelope.identity.operation_id != candidate.operation_id
            or envelope.version_guard.query_epochs != (query,)
            or envelope.version_guard.read_versions != snapshot.versions
            or candidate.source_audience != envelope.authority.audience
            or (candidate.access_epoch, candidate.delete_epoch) != (
                envelope.version_guard.access_epoch,
                envelope.version_guard.delete_epoch,
            )):
        raise ValueError("dispatch candidate does not match the current graph guard")

    linked = tuple((proposal.domain, write) for proposal in bundle.proposals
                   for write in proposal.typed_writes)
    rebuilt = validate_dispatch_candidate_writes(
        linked, namespace=namespace, identity=envelope.identity,
        read_versions=snapshot.versions,
        source_refs=envelope.source_qualification.source_refs,
        access_epoch=candidate.access_epoch,
        delete_epoch=candidate.delete_epoch,
        query_epoch=candidate.query_epoch,
    )
    if rebuilt is None or rebuilt != replace(
            candidate, status="source_hold", source_audience=(),
            source_proof_versions=(), source_proof_digest=None):
        raise ValueError("staged D08/D09 candidate differs from qualified identity")

    rows = {write.key.type_name: write.value for _, write in linked
            if write.key.type_name in {
                "d08.action_intent.v1", "d09.verified_segment_batch.v1",
            }}
    action_spec = next(spec for spec in GoalExecutionProvider().register_types()
                       if spec.name == "d08.action_intent.v1")
    batch_spec = next(spec for spec in D09ExpressionProvider.register_types()
                      if spec.name == "d09.verified_segment_batch.v1")
    intent = action_spec.validator(rows["d08.action_intent.v1"])
    batch = rows["d09.verified_segment_batch.v1"]
    batch_spec.validator(batch)
    if batch["valid_until"] < now_utc:
        raise ValueError("verified segment batch expired")

    # The snapshot was supplied by the graph coordinator; compare every
    # positive and negative read with SQLite rather than trusting that object.
    for atom in snapshot.atoms:
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?",
            (atom.key.token, *namespace.as_tuple),
        ).fetchone()
        if ((row is None and (atom.revision != 0 or atom.valid))
                or (row is not None and (atom.revision != row[0]
                    or atom.valid != bool(row[2])
                    or atom.value != json.loads(row[1])))):
            raise ValueError("dispatch graph read changed in the transaction")
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (epochs or (0, 0)) != (candidate.access_epoch, candidate.delete_epoch):
        raise ValueError("source access or deletion epoch changed")

    source_check = D06DomainProvider.provide_required_check(
        intent, SourceGrantRead(snapshot, candidate.source_audience,
                                "expression", True, True),
        valid_until=batch["valid_until"],
    )
    if (source_check.result != "pass" or source_check.coverage != "full"
            or source_check.valid_until < now_utc):
        raise ValueError("current D06 source check is incomplete")
    atoms = {atom.key.token: atom for atom in snapshot.atoms}
    proof = []
    for item in source_check.input_versions:
        atom = atoms.get(item.ref)
        if (atom is None or not atom.valid or atom.revision != item.version
                or atom.key.type_name not in {"memory.source", "memory.access"}):
            raise ValueError("source proof read is incomplete")
        proof.append((item.ref, item.version, canonical_digest(atom.value)))
    if (not proof or candidate.source_proof_versions != tuple(
            (ref, revision) for ref, revision, _ in proof)
            or candidate.source_proof_digest != canonical_digest(proof)):
        raise ValueError("source proof differs from the qualified candidate")

    projection = read_current_dispatch_projection(db, namespace, snapshot, query)
    d08_facts = read_current_d08_conflict_facts(db, namespace, snapshot, query)
    lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
    reservation = db.execute(
        "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (lease.lease_id, envelope.identity.operation_id),
    ).fetchone()
    if (lease.state != "active"
            or (lease.bot_id, lease.persona_id) != namespace.as_tuple
            or reservation is None or reservation[2] != "reserved"):
        raise ValueError("current D11 reservation is absent")
    ceiling = json.loads(reservation[1])
    if (type(ceiling) is not dict or not ceiling
            or any(type(amount) is not int or amount <= 0
                   or lease.reserved.get(name, 0) < amount
                   for name, amount in ceiling.items())):
        raise ValueError("current D11 reservation identity differs")
    # Reuse the coordinator's exact operation identity; a second encoding of
    # this digest would eventually drift from the writer.
    from ..graph_coordinator import budget_operation_digest

    digest = budget_operation_digest(envelope, lease.lease_id, ceiling)
    if reservation[0] != digest:
        raise ValueError("current D11 reservation identity differs")
    return CurrentAdmissionFactsV1(
        candidate.digest, canonical_digest(source_check), projection,
        d08_facts, lease, digest, ceiling,
    )


__all__ = ["CurrentAdmissionFactsV1", "read_current_admission_facts"]
