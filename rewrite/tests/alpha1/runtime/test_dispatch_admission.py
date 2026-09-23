"""D11 admission identities are durable, typed, and closed without trust."""

from dataclasses import asdict, replace
import json
import sqlite3
import time

import pytest

from sylanne3.contracts import StaleRead
from sylanne3.dispatch_runtime import DispatchRequest
from sylanne3.domains.d06 import D06DomainProvider, SourceGrantRead
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim, SegmentCandidate,
)
from sylanne3.graph_coordinator import (
    GraphCoordinator, UnavailableGuard, budget_operation_digest,
)
from sylanne3.graph_types import AtomKey, GraphWrite, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
)
from sylanne3.runtime.dispatch_admission import (
    DispatchAdmissionReceiptV1, DispatchAdmissionV1, install_schema,
    load_admission,
)
from sylanne3.runtime_contracts import (
    CheckReceipt, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard,
    VersionedRef, canonical_digest,
)
from sylanne3.runtime_journal import BudgetConstraint, RecoveryConstraintFootprint

from test_dispatch_admission_preflight import _candidates
from test_dispatch_candidate_graph import _Budget, _Resources, _bundle, _json, _ready


def _qualified_bundle(coordinator, authority, lease, providers):
    """Use actual D06 source/access graph versions for the source check."""
    source = source_key("bot", "persona", "source-1")
    access = access_key("bot", "persona", "source-1")
    _schema, intent, _batch, _request, _receipts, grant = _candidates(
        source_ref=source.token, include_grant=True)
    identity = replace(intent.identity, canonical_input_digest=canonical_digest({
        "input_refs": [],
    }))
    pinned = (VersionedRef(source.token, 1), VersionedRef(access.token, 1))
    specs = tuple(replace(spec, criteria_version=source.token,
                          required_input_versions=pinned)
                  for spec in intent.required_checks)
    intent = replace(intent, identity=identity, required_checks=specs)
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema("schema:one", "message", False, specs))
    refs = tuple("check:" + canonical_digest({
        "kind": spec.check_kind, "provider": spec.provider_id,
        "subject": spec.subject_ref, "action": spec.action_ref,
        "purpose": spec.purpose, "criteria_version": spec.criteria_version,
        "input_versions": spec.required_input_versions,
    }) for spec in specs)
    valid_until = time.time() + 3600
    grant = replace(
        grant, required_check_refs=refs, valid_until=valid_until,
        segment_grants=tuple(replace(segment, required_check_refs=refs,
                                     valid_until=valid_until)
                             for segment in grant.segment_grants),
    )
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    claims = (ExpressionClaim(
        "claim:one", "Hello", ClaimKind.EXTERNAL_FACT, (source.token,),
        ("entity:user",), ("expression",), "disclosure:one",
    ),)
    expression = D09ExpressionProvider()
    blueprint = expression.prepare_blueprint(
        grant, "scene:one", 1, claims, now=1.0).blueprint
    assert blueprint is not None
    batch = expression.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:one", "Hello", (use,),
                          ("answer",), (), 0.0),), now=1.0,
    )
    owner = Owner("activity", "bot", "persona", identity.activity_id)
    values = (
        ("d08.action_intent.v1", intent.action_id, intent),
        ("d08.action_schema.v1", schema.schema_ref, schema),
        ("d08.communication_intent_grant.v1", grant.grant_id, grant),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    writes = tuple(GraphWrite(
        AtomKey(owner, kind, name),
        value if isinstance(value, dict) else _json(asdict(value)),
    ) for kind, name, value in values)
    snapshot = coordinator.read_snapshot(
        authority, lease, (source, access) + tuple(write.key for write in writes))
    guard = VersionGuard(
        snapshot.versions,
        (QueryEpoch(authority.namespace, "all", snapshot.epochs[0].revision),),
        0, 0, coordinator._GraphCoordinator__store._registry.catalogue_hash,
        "scheme-1", "operator-1", "policy-1", (), (), (),
    )
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA, identity, authority, guard,
        SourceQualification((source.token,), "observed", 1.0, 2.0,
                            "external_observation", "eligible", 0.8,
                            "not_applicable"),
        (), "parent", valid_until, 100.0, "character-1", (),
    )
    proposals = (
        DomainProposal("d08", "d08.proposal.v1",
                       providers[1].descriptor.request_schema_hash,
                       envelope, writes[:3], DependencySet(), (), ()),
        DomainProposal("d09", "d09.proposal.v1",
                       providers[2].descriptor.request_schema_hash,
                       envelope, writes[3:], DependencySet(), (), ()),
    )
    return DomainBundle(envelope, proposals, (), (), (), (), (), (), ()), (
        intent, schema, grant, batch,
    )


class _TestAdmissionIssuer:
    """Test-only issuer; its non-D06 domain decisions are fixture attestations."""

    def __init__(self):
        self.request = None
        self.admission = None
        self.intent = None
        self.schema = None
        self.grant = None
        self.batch = None

    def bind(self, values):
        self.intent, self.schema, self.grant, self.batch = values

    def issue_dispatch_admission(self, bundle, snapshot, candidate, db, *,
                                 graph_incarnation, now_utc):
        intent, schema, grant, batch = (
            self.intent, self.schema, self.grant, self.batch)
        segment = batch["segments"][0]
        identity = intent.identity
        request = DispatchRequest(
            "bot/persona", identity.operation_id, identity.activity_id,
            identity.effect_id, identity.attempt_id,
            canonical_digest({"command": identity.operation_id}),
            "payload:one", segment["payload_digest"], "platform:test",
            grant.required_check_refs, 1, 1, 1, "content:one",
            batch["cancellation_epoch"],
            RecoveryConstraintFootprint(
                "bot/persona", identity.activity_id, identity.effect_id,
                communication_action=grant.communication_action_id,
                contact_id=grant.contact_id, segment_id=segment["segment_id"],
                budgets=(BudgetConstraint("parent", "0", "1", "1"),),
            ),
            False, segment["segment_authorization_ref"],
            grant.segment_manifest_digest, 0, 1,
        )
        receipts = []
        for spec in schema.required_checks:
            if spec.check_kind == "source_grant":
                receipt = D06DomainProvider.provide_required_check(
                    intent, SourceGrantRead(
                        snapshot, ("entity:user",), "expression", True, True),
                    valid_until=batch["valid_until"],
                )
            else:
                receipt = CheckReceipt(
                    spec.check_kind, spec.subject_ref, spec.action_ref,
                    spec.purpose, spec.required_input_versions,
                    "full", "pass", batch["valid_until"], spec.provider_id,
                )
            receipts.append(receipt)
        lease = get_budget_lease(db, "parent")
        admission = DispatchAdmissionV1(
            namespace="bot/persona", graph_incarnation=graph_incarnation,
            activity_id=identity.activity_id, effect_id=identity.effect_id,
            attempt_id=identity.attempt_id, operation_id=identity.operation_id,
            dispatch_generation=1, admission_ref="admission:one",
            candidate_digest=candidate.digest, request_digest=canonical_digest(request),
            action_intent_digest=candidate.action_digest,
            action_intent_schema_version="d08.action_intent.v1",
            action_schema_digest=candidate.schema_digest,
            action_schema_version="d08.action_schema.v1",
            required_checks_digest=canonical_digest(schema.required_checks),
            required_checks_schema_version="d08.required_check_spec.v1",
            grant_digest=candidate.grant_digest, batch_digest=candidate.batch_digest,
            segment_index=0, payload_digest=segment["payload_digest"],
            account_ref="account:test", destination_ref="destination:test",
            scene_ref=batch["scene_ref"], owner_head_ref="owner:test",
            role_ref="role:test", binding_ref="binding:test",
            object_ref=intent.target_ref, action_ref=intent.action_id,
            purpose=intent.purpose, audience=("entity:user",),
            graph_reads=tuple((item.key.token, item.revision)
                              for item in snapshot.versions),
            query_epoch=snapshot.epochs[0].revision, access_epoch=0, delete_epoch=0,
            check_receipts=tuple(receipts),
            budget_parent_lease_ref="parent", budget_lease_ref="parent",
            budget_reservation_operation_id=identity.operation_id,
            budget_reservation_digest=budget_operation_digest(
                bundle.envelope, "parent", {"cpu_ms": 1}),
            budget_ceiling={"cpu_ms": 1}, budget_currency=lease.currency,
            budget_version=lease.version, contact_reservation_ref=None,
            utc_deadline="2099-01-01T00:00:00Z",
            clock_policy_ref="clock:test", clock_policy_digest="0" * 64,
        )
        self.request, self.admission = request, admission
        return request, admission

    def verify_required_check(self, spec, receipt, snapshot, _db):
        versions = {item.key.token: item.revision for item in snapshot.versions}
        observed = all(versions.get(item.ref) == item.version
                       for item in spec.required_input_versions)
        expected = next(item for item in self.admission.check_receipts
                        if item.check_kind == spec.check_kind)
        return observed and receipt == expected

    def verify_domain_context(self, admission, snapshot, _db):
        return (admission is self.admission
                and admission.scene_ref == self.batch["scene_ref"]
                and len(snapshot.atoms) == len(admission.graph_reads))

    def verify_command_provenance(self, request, admission, _db):
        return (request is self.request and admission is self.admission
                and canonical_digest(request) == admission.request_digest)

    def verify_journal_constraints(self, request, admission):
        return (request is self.request and admission is self.admission
                and request.footprint.effect_id == admission.effect_id)


def _admission():
    _schema, _intent, _batch, _request, receipts = _candidates()
    return DispatchAdmissionV1(
        namespace="bot/persona", graph_incarnation="incarnation:one",
        activity_id="activity:one", effect_id="effect:one",
        attempt_id="attempt:one", operation_id="operation:one",
        dispatch_generation=1, admission_ref="admission:one",
        candidate_digest="0" * 64, request_digest="1" * 64,
        action_intent_digest="2" * 64,
        action_intent_schema_version="d08.action_intent.v1",
        action_schema_digest="3" * 64,
        action_schema_version="d08.action_schema.v1",
        required_checks_digest="4" * 64,
        required_checks_schema_version="d08.required_check_spec.v1",
        grant_digest="5" * 64, batch_digest="6" * 64,
        segment_index=0, payload_digest="7" * 64,
        account_ref="account:one", destination_ref="destination:one",
        scene_ref="scene:one", owner_head_ref="owner:one",
        role_ref="role:one", binding_ref="binding:one",
        object_ref="entity:user", action_ref="action:one",
        purpose="expression", audience=("entity:user",),
        graph_reads=(("source:one", 1),), query_epoch=1,
        access_epoch=0, delete_epoch=0, check_receipts=receipts,
        budget_parent_lease_ref="parent:one", budget_lease_ref="parent:one",
        budget_reservation_operation_id="operation:one",
        budget_reservation_digest="8" * 64,
        budget_ceiling={"cpu_ms": 1}, budget_currency="USD",
        budget_version=1, contact_reservation_ref=None,
        utc_deadline="2099-01-01T00:00:00Z", clock_policy_ref="clock:one",
        clock_policy_digest="9" * 64,
    )


def test_typed_receipt_round_trip_and_corrupt_digest_rejected():
    admission = _admission()
    digest = canonical_digest({
        "admission_digest": admission.digest, "graph_revision": 2,
        "graph_epoch": 3,
    })
    receipt = DispatchAdmissionReceiptV1(admission, 2, 3, digest)
    db = sqlite3.connect(":memory:")
    install_schema(db)
    db.execute(
        "INSERT INTO graph_dispatch_admissions VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("bot", "persona", admission.admission_ref, admission.operation_id,
         admission.effect_id, admission.digest, json.dumps(asdict(admission)),
         2, 3, digest),
    )
    assert load_admission(db, NamespaceId("bot", "persona"), "admission:one") == receipt
    db.execute(
        "UPDATE graph_dispatch_admissions SET receipt_digest=?",
        ("f" * 64,),
    )
    with pytest.raises(ValueError, match="receipt digest differs"):
        load_admission(db, NamespaceId("bot", "persona"), "admission:one")
    db.close()


def test_missing_receipts_and_budget_cannot_form_admission():
    admission = _admission()
    with pytest.raises(ValueError, match="actual typed check receipts"):
        replace(admission, check_receipts=())
    with pytest.raises(ValueError, match="positive budget ceiling"):
        replace(admission, budget_ceiling={})
    with pytest.raises(ValueError, match="graph read set"):
        replace(admission, graph_reads=())


def test_graph_read_race_leaves_neither_candidate_nor_admission(tmp_path):
    store, coordinator, authority, lease, providers, _registry = _ready(tmp_path)
    bundle = _bundle(coordinator, authority, lease, providers)
    source = bundle.envelope.source_qualification.source_refs[0]
    with store._lock:
        store._db.execute(
            "UPDATE graph_atoms SET revision=revision+1 WHERE token=?", (source,),
        )
    with pytest.raises(StaleRead):
        coordinator.commit_domain_bundle(bundle, lease)
    assert coordinator.get_dispatch_candidate_evidence(
        authority, lease, bundle.envelope.identity.operation_id) is None
    with store._lock:
        assert store._db.execute(
            "SELECT 1 FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
        assert store._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='graph_dispatch_admissions'"
        ).fetchone() is None
    store.close()


def test_committed_candidate_does_not_create_admission_without_issuer(tmp_path):
    store, coordinator, authority, lease, providers, _registry = _ready(tmp_path)
    bundle = _bundle(coordinator, authority, lease, providers)
    assert coordinator.commit_domain_bundle(bundle, lease).status == "committed"
    with store._lock:
        receipt = store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone()
        assert receipt is not None
        assert "dispatch_candidate" in json.loads(receipt[0])
        assert "dispatch_admission" not in json.loads(receipt[0])
        assert store._db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='graph_dispatch_admissions'"
        ).fetchone() is None
    store.close()


def _issuer_case(tmp_path):
    store, _old, _authority, _lease, providers, _registry = _ready(tmp_path)
    bootstrap = object()
    issuer = _TestAdmissionIssuer()
    coordinator = GraphCoordinator(
        store, bootstrap, d02_issuer=_Resources(), d11_issuer=_Budget(),
        dispatch_admission_issuer=issuer,
    )
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        coordinator.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash,
        )
    coordinator.register_provider(
        bootstrap, "d11", D11RuntimeProvider(),
        D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    )
    namespace = NamespaceId("bot", "persona")
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=namespace,
        domains=("d06", "d08", "d09", "d11"), activation_generation=1,
    )
    from sylanne3.runtime_contracts import AuthorityContext

    authority = AuthorityContext(
        "host", "d06", capability, namespace, ("event", "activity"),
        "expression", ("entity:user",), "policy-1", 1,
    )
    bundle, values = _qualified_bundle(coordinator, authority, lease, providers)
    issuer.bind(values)
    return store, coordinator, authority, lease, bundle, issuer


def test_same_graph_transaction_persists_test_issuer_admission(tmp_path):
    """The internal path accepts a test clock; no production issuer is installed."""
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(tmp_path)
    namespace = authority.namespace
    committed = coordinator._commit_domain_bundle_fenced(
        bundle, lease, now_utc=2.0,  # explicit test clock at the internal seam
    )
    assert committed.status == "committed"
    with store._lock:
        row = store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone()
        assert row is not None
        assert json.loads(row[0])["dispatch_admission"]["ref"] == "admission:one"
        stored = load_admission(store._db, namespace, "admission:one")
    assert stored is not None
    assert stored.admission == issuer.admission
    assert stored.graph_epoch == committed.invalidated_epochs[0].revision
    assert coordinator.commit_domain_bundle(bundle, lease).status == "duplicate"
    store.close()
    reopened = sqlite3.connect(tmp_path / "candidate.db")
    try:
        assert load_admission(reopened, namespace, "admission:one") == stored
    finally:
        reopened.close()


def test_public_bundle_without_trusted_admission_clock_rolls_back(tmp_path):
    store, coordinator, _authority, lease, bundle, _issuer = _issuer_case(tmp_path)
    with pytest.raises(UnavailableGuard, match="trusted dispatch admission clock"):
        coordinator.commit_domain_bundle(bundle, lease)
    with store._lock:
        assert store._db.execute(
            "SELECT 1 FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
        assert store._db.execute(
            "SELECT 1 FROM graph_events WHERE event_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
        assert store._db.execute(
            "SELECT 1 FROM runtime_budget_reservations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
    store.close()
