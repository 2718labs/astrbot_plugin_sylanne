"""C04 must commit five real domain writes and D02/D11 ledgers together."""

from dataclasses import asdict, replace
import hashlib
from pathlib import Path

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.domains.d02 import BodyDomain, BodyReservation, BodyState, SettlementResult
from sylanne3.domains.d04 import AffectProvider
from sylanne3.domains.d04.affect import AffectAxis, AffectScheme, RecollectionExperience
from sylanne3.domains.d06 import (
    CandidateItem, CandidateSet, D06DomainAdapter, D06DomainProvider,
    RecollectionContext,
)
from sylanne3.domains.d07 import (
    CurrentInterpretationCandidate, D07DomainProvider, EvidenceStatus, Stance,
)
from sylanne3.graph_coordinator import (
    AuthorityDenied, GraphCoordinator, budget_operation_digest,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphWrite, Owner, TypeRegistry
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, get_budget_lease,
    predict_budget_settlement,
)
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, RuntimeCostSettlement,
    RuntimeOutboxValue, cost_settlement_graph_write, job_graph_write,
    outbox_graph_write, runtime_cost_settlement_key, runtime_job_key,
    runtime_outbox_key,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, ResourceOutcome, ResourceQuote, build_runtime_issuers,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainProposal,
    NamespaceId, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)


def _json(value):
    if isinstance(value, tuple):
        return [_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _json(item) for key, item in value.items()}
    return value


class C04Harness:
    def __init__(self, root: Path, *, bind_scheme: bool = True):
        self.namespace = NamespaceId("bot", "persona")
        scheme = AffectScheme(
            "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameter-1",
            "coupling-1", (AffectAxis("care", "normalized", "care response"),),
            (("recovery_rate", 0.01, 2.0),),
        )
        self.providers = {
            "d02": BodyDomain(),
            "d04": AffectProvider(active_scheme=scheme if bind_scheme else None),
            "d06": D06DomainProvider(), "d07": D07DomainProvider(),
            "d11": D11RuntimeProvider(),
        }
        self.registry = TypeRegistry()
        for provider in self.providers.values():
            for spec in provider.type_specs():
                self.registry.register(spec)
        self.store = GraphStore(root / "graph.db", self.registry)
        self.bootstrap = object()
        self.d02, self.d11 = build_runtime_issuers(
            b"c04-signer-key" * 3,
            outcome_verifier=lambda outcome, quote, db:
                outcome.provider_receipt_ref == "provider-receipt-c04"
                and outcome.operation_id == quote.operation_id,
        )
        with self.store._lock:
            install_issuer_schema(self.store._db)
            create_budget_lease(self.store._db, BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"cpu_ms": 1000, "model_microusd": 1000}, {}, {}, {},
                1, "active",
            ), "install-parent", "0" * 64)
        self.coordinator = GraphCoordinator(
            self.store, self.bootstrap, d02_issuer=self.d02, d11_issuer=self.d11,
        )
        for domain, provider in self.providers.items():
            schema = D11_PROPOSAL_SCHEMA if domain == "d11" else (
                "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1"
            )
            self.coordinator.register_provider(
                self.bootstrap, domain, provider, schema,
                provider.descriptor.request_schema_hash,
            )
        self.lease, capability = self.coordinator.grant(
            self.bootstrap, actor="host", issuer_domain="d06",
            namespace=self.namespace, domains=tuple(self.providers),
            activation_generation=1,
        )
        self.authority = AuthorityContext(
            "host", "d06", capability, self.namespace,
            ("event", "activity"), "context", ("owner",), "policy-1", 1,
        )
        for kind, ref, version in (
            ("scheme", "current", "scheme-1"),
            ("operator", "current", "operator-1"),
            ("policy", "current", "policy-1"),
            ("activation", "current", 1),
            ("focus_lease", "focus-1", 4),
            ("resource_lease", "quote-c04", 1),
        ):
            self.coordinator.set_guard_version(
                self.bootstrap, self.namespace, kind, ref, version,
            )
        MemoryRepository(self.store, "bot", "persona").ingest(
            Event(Scope("bot", "persona", "session"), "source-ingress", 1.0,
                  "ingress", {}),
            SourceRecord("source-1", "shared evening", "alice", "observed",
                         "confirmed", 1.0, 2.0, "family-1", ("owner",),
                         ("context",)),
        )

    def close(self):
        self.store.close()

    def bundle(self):
        activity, operation = "activity-c04", "operation-c04"
        source = source_key("bot", "persona", "source-1")
        access = access_key("bot", "persona", "source-1")
        candidates = CandidateSet(
            "set-c04", (CandidateItem(
                "candidate-1", "source-1", "family-1", "association",
                ("context",), 0.8, "observed",
            ),), "complete", access_epoch=0, delete_epoch=0,
        )
        handoff = self.providers["d07"].select_recollection(
            activity_id=activity, focus_epoch=4, candidates=candidates,
            selected_candidate_ids=("candidate-1",),
        )
        ticket = handoff.selection_ticket
        adapter = D06DomainAdapter(self.namespace)
        recollection = adapter.prepare_recollection(
            ticket, candidates, RecollectionContext((), (), ()),
        )
        owner = Owner("activity", "bot", "persona", activity)
        recollection_key = AtomKey(owner, "d06.recollection.v1",
                                   recollection.recollection_id)
        choice_key = AtomKey(owner, "d07.selection_ticket.v1", ticket.ticket_id)
        interpretation_key = AtomKey(owner, "d07.current_interpretation.v1", "meaning-c04")
        feeling_key = AtomKey(owner, "d04.recollection_experience.v1", "feeling-c04")
        settlement_key = AtomKey(owner, "d02.settlement.v1", "body-c04")
        cost_key = runtime_cost_settlement_key("bot", "persona", activity, "cost-c04")
        job_key = runtime_job_key("bot", "persona", activity, "job-c04")
        outbox_key = runtime_outbox_key("bot", "persona", activity, "outbox-c04")
        keys = (source, access, recollection_key, choice_key, interpretation_key,
                feeling_key, settlement_key, cost_key, job_key, outbox_key)
        snapshot = self.coordinator.read_snapshot(self.authority, self.lease, keys)
        inputs = (ticket.ticket_id, candidates.candidate_set_id)
        ceiling = {"cpu_ms": 200, "model_microusd": 300}
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity(activity, None, "attempt-c04", "realize-recollection",
                              operation, canonical_digest({"input_refs": list(inputs)})),
            self.authority,
            VersionGuard(
                snapshot.versions,
                (QueryEpoch(self.namespace, "all", snapshot.epochs[0].revision),),
                0, 0, self.registry.catalogue_hash, "scheme-1", "operator-1",
                "policy-1", (), (VersionedRef("focus-1", 4),),
                (VersionedRef("quote-c04", 1),),
            ),
            SourceQualification((source.token,), "observed", 1.0, 2.0,
                                "external_observation", "eligible", 0.8,
                                "not_applicable"),
            inputs, "parent", 4_102_444_800.0, 100.0, "character-1",
            ("trigger-c04",),
        )
        with self.store._lock:
            self.d02.issue_quote(self.store._db, ResourceQuote(
                "quote-c04", 1, "bot", "persona", activity, operation, None,
                "parent", "encode", "snapshot-c04", envelope.deadline_utc,
                "resource-c04", job_key.token, (outbox_key.token,),
                (settlement_key.token,), ceiling, None, 4_102_444_900.0,
            ))
            self.d11.issue_budget_grant(self.store._db, BudgetLeaseGrant(
                "grant-c04", 1, "bot", "persona", "parent", "USD",
                ceiling, ("encode",), 4_102_445_000.0, "policy-1",
            ))
            self.d02.issue_outcome(self.store._db, ResourceOutcome(
                "outcome-c04", 1, "quote-c04", "bot", "persona", activity,
                operation, ceiling, False, "provider-receipt-c04",
            ))
            job = self.d11.job_for(envelope, self.store._db)
            durable_lease = get_budget_lease(self.store._db, "parent")
        digest = budget_operation_digest(envelope, "parent", ceiling)
        prediction = predict_budget_settlement(
            durable_lease, operation, digest, ceiling, ceiling, inline_reserve=True,
        )
        cost = RuntimeCostSettlement(
            "bot", "persona", activity, operation, None, "cost-c04", "parent",
            "USD", operation, "settled", ceiling, ceiling, {}, "settle",
            operation, prediction.receipt_json_sha256, None, False,
        )
        interpretation = CurrentInterpretationCandidate(
            "meaning-c04", activity, "question:memory", "perhaps it matters now",
            Stance.SUSPEND, 0.4, EvidenceStatus.INSUFFICIENT,
            (source.token,), ("family-1",), ("present meaning is uncertain",),
        )
        d07 = self.providers["d07"].recollection_support_proposal(
            envelope, handoff, interpretation, source_dependencies=(source,),
        )
        feeling = RecollectionExperience(
            "feeling-c04", activity, recollection_key.token, source.token,
            (source.token,), "mood-c04", (source.token,), (0.2, 0.4), (-0.2, 0.1),
            "coupling-c04", "coupling-1",
        )
        d04 = self.providers["d04"].proposal_for(
            envelope,
            typed_writes=(GraphWrite(feeling_key, _json(asdict(feeling))),),
            dependencies=DependencySet(), contribution_keys=("feeling-c04",),
            required_bundle_parts=("experience",),
        )
        body = SettlementResult(
            BodyState("profile-c04", 1, 0.8, {"encode": 0.1}, 0.0, 1.0),
            BodyReservation("reserve-c04", "quote-c04", "effect-c04", 0.1,
                            0.0, ("encode",), "settled"),
            False, 0.0,
        )
        d02 = DomainProposal(
            "d02", "d02.proposal.v1",
            self.providers["d02"].descriptor.request_schema_hash, envelope,
            (BodyDomain.settlement_write(self.namespace, activity, "body-c04", body),),
            DependencySet(), (), (),
        )
        outbox = RuntimeOutboxValue(
            "bot", "persona", activity, operation, None, "outbox-c04",
            job.job_id, job_key.token, recollection.recollection_id,
            f"d06:c04:{activity}", "pending", 1,
        )
        d11 = DomainProposal(
            "d11", D11_PROPOSAL_SCHEMA,
            self.providers["d11"].descriptor.request_schema_hash, envelope,
            (cost_settlement_graph_write(cost), job_graph_write(job),
             outbox_graph_write(outbox, job_key)),
            DependencySet(current_invalidation=tuple(
                item for item in snapshot.versions if item.key == job_key
            )), (), (),
        )
        return adapter.assemble_recollection_bundle(
            envelope, ticket, candidates,
            RecollectionContext((interpretation_key.token,),
                                (feeling_key.token,), ()),
            supporting_proposals=(d07, d04, d02, d11),
            choice_ref=choice_key.token,
            d02_settlement_ref=settlement_key.token,
            d11_cost_settlement_ref=cost_key.token,
            persistent_job_ref=job_key.token,
            outbox_ref=outbox_key.token,
        )


def test_c04_five_domain_commit_and_budget_ledger_are_atomic(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        bundle = harness.bundle()
        receipt = harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        assert receipt.status == "committed"
        assert {item.key.token for item in receipt.write_versions} == {
            write.key.token for proposal in bundle.proposals
            for write in proposal.typed_writes
        }
        db = harness.store._db
        assert db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM graph_outbox_jobs").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 1
        writes = {write.key for proposal in bundle.proposals
                  for write in proposal.typed_writes}
        atoms = harness.store.graph_snapshot(tuple(writes)).atoms
        assert {atom.key for atom in atoms if atom.valid} == writes
        assert {proposal.domain for proposal in bundle.proposals} == {
            "d02", "d04", "d06", "d07", "d11",
        }
        cost = next(atom for atom in atoms
                    if atom.key.type_name == "runtime.cost_settlement")
        budget_json = db.execute(
            "SELECT receipt_json FROM runtime_budget_operations "
            "WHERE operation_id='operation-c04' AND phase='settle'"
        ).fetchone()[0]
        assert cost.value["budget_receipt_digest"] == hashlib.sha256(
            budget_json.encode("utf-8")
        ).hexdigest()
        assert get_budget_lease(db, "parent").used == {
            "cpu_ms": 200, "model_microusd": 300,
        }
    finally:
        harness.close()


def test_c04_unbound_affect_scheme_fails_closed(tmp_path):
    harness = C04Harness(tmp_path, bind_scheme=False)
    try:
        bundle = harness.bundle()
        with pytest.raises(ValueError, match="active D04 scheme is required"):
            harness.coordinator.commit_domain_bundle(bundle, harness.lease)
        assert harness.store._db.execute(
            "SELECT COUNT(*) FROM graph_bundle_operations"
        ).fetchone()[0] == 0
    finally:
        harness.close()


def test_c04_rejected_cost_receipt_rolls_back_all_domains(tmp_path):
    harness = C04Harness(tmp_path)
    try:
        bundle = harness.bundle()
        d11 = next(proposal for proposal in bundle.proposals if proposal.domain == "d11")
        cost = d11.typed_writes[0]
        bad_cost = replace(cost, value={**cost.value, "budget_receipt_digest": "f" * 64})
        bad_d11 = replace(d11, typed_writes=(bad_cost, *d11.typed_writes[1:]))
        bad_bundle = replace(bundle, proposals=tuple(
            bad_d11 if proposal.domain == "d11" else proposal
            for proposal in bundle.proposals
        ))
        with pytest.raises(AuthorityDenied, match="D11 cost graph atom differs"):
            harness.coordinator.commit_domain_bundle(bad_bundle, harness.lease)
        db = harness.store._db
        assert db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM graph_outbox_jobs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM runtime_jobs").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM runtime_budget_operations").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM runtime_budget_reservations").fetchone()[0] == 0
        assert get_budget_lease(db, "parent").used == {}
        assert get_budget_lease(db, "parent").reserved == {}
    finally:
        harness.close()
