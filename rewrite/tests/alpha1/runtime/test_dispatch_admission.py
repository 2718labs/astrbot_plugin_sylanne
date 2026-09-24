"""D11 admission identities are durable, typed, and closed without trust."""

from dataclasses import asdict, replace
import json
import sqlite3
import time

import pytest

from sylanne3.contracts import Event, Scope, StaleRead
from sylanne3.domains.d03 import ContextProvider, RoleBinding
from sylanne3.domains.d05 import BoundaryRule, RelationshipProvider
from sylanne3.dispatch_runtime import DispatchRequest
from sylanne3.domains.d06 import D06DomainProvider, SourceGrantRead
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim, SegmentCandidate,
)
from sylanne3.graph_coordinator import (
    GraphCoordinator, UnavailableGuard, budget_operation_digest,
)
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.host.identity import astrbot_namespace
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner
from sylanne3.memory_repository import MemoryRepository
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.budget import BudgetLease, create_budget_lease
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
)
from sylanne3.runtime.dispatch_admission import (
    DispatchAdmissionReceiptV1, DispatchAdmissionV1, install_schema,
    load_admission, load_request,
)
from sylanne3.runtime.dispatch_candidate import dispatch_segment_payload_ref
from sylanne3.runtime_contracts import (
    CheckReceipt, CommandEnvelope, DependencySet, DomainBundle, DomainProposal,
    NamespaceId, QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard,
    VersionedRef, canonical_digest,
)
from sylanne3.runtime_journal import BudgetConstraint, RecoveryConstraintFootprint

from test_dispatch_admission_preflight import _candidates
from test_dispatch_candidate_graph import (
    _Budget, _Resources, _bundle, _json, _ready, _registry,
)


def _qualified_bundle(coordinator, authority, lease, providers, *,
                      projection_keys=(), scene_ref="scene:one"):
    """Use actual D06 source/access graph versions for the source check."""
    bot, persona = authority.namespace.as_tuple
    audience = authority.audience[0]
    source = source_key(bot, persona, "source-1")
    access = access_key(bot, persona, "source-1")
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
        audiences=(audience,),
        segment_grants=tuple(replace(segment, required_check_refs=refs,
                                     valid_until=valid_until)
                             for segment in grant.segment_grants),
    )
    use = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    claims = (ExpressionClaim(
        "claim:one", "Hello", ClaimKind.EXTERNAL_FACT, (source.token,),
        (audience,), ("expression",), "disclosure:one",
    ),)
    expression = D09ExpressionProvider()
    blueprint = expression.prepare_blueprint(
        grant, scene_ref, 1, claims, now=1.0).blueprint
    assert blueprint is not None
    batch = expression.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:one", "Hello", (use,),
                          ("answer",), (), 0.0),), now=1.0,
    )
    owner = Owner("activity", bot, persona, identity.activity_id)
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
        authority, lease, (source, access) + tuple(projection_keys)
        + tuple(write.key for write in writes))
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
        self.last_now_utc = None
        self.intent = None
        self.schema = None
        self.grant = None
        self.batch = None
        self.payload_ref_override = None
        self.namespace = NamespaceId("bot", "persona")
        self.audience = "entity:user"
        self.astrbot_route = False
        self.platform_name_override = None

    def bind(self, values):
        self.intent, self.schema, self.grant, self.batch = values

    def issue_dispatch_admission(self, bundle, snapshot, candidate, db, *,
                                 graph_incarnation, now_utc):
        self.last_now_utc = now_utc
        intent, schema, grant, batch = (
            self.intent, self.schema, self.grant, self.batch)
        segment = batch["segments"][0]
        identity = intent.identity
        namespace = "/".join(self.namespace.as_tuple)
        request = DispatchRequest(
            namespace, identity.operation_id, identity.activity_id,
            identity.effect_id, identity.attempt_id,
            canonical_digest({"command": identity.operation_id}),
            (self.payload_ref_override or dispatch_segment_payload_ref(
                candidate.batch_ref, 0)),
            segment["payload_digest"], "platform:test",
            grant.required_check_refs, 1, 1, 1, "content:one",
            batch["cancellation_epoch"],
            RecoveryConstraintFootprint(
                namespace, identity.activity_id, identity.effect_id,
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
                        snapshot, (self.audience,), "expression", True, True),
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
            namespace=namespace, graph_incarnation=graph_incarnation,
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
            account_ref=(json.dumps(["platform-1",
                                     self.platform_name_override or "aiocqhttp", "bot-1"],
                                    separators=(",", ":"))
                         if self.astrbot_route else "account:test"),
            destination_ref=self.audience if self.astrbot_route else "destination:test",
            scene_ref=batch["scene_ref"], owner_head_ref="owner:test",
            role_ref="role:test", binding_ref="binding:test",
            object_ref=intent.target_ref, action_ref=intent.action_id,
            purpose=intent.purpose, audience=(self.audience,),
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


class _ClockBudget(_Budget):
    def __init__(self):
        self.last_now_utc = None

    def admit_runtime(self, bundle, db, *, now_utc=None):
        self.last_now_utc = now_utc
        return super().admit_runtime(bundle, db, now_utc=now_utc)


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
    db.execute("""CREATE TABLE graph_dispatch_admissions (
        bot TEXT NOT NULL, persona TEXT NOT NULL, admission_ref TEXT NOT NULL,
        operation_id TEXT NOT NULL, effect_id TEXT NOT NULL,
        admission_digest TEXT NOT NULL, admission_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
        receipt_digest TEXT NOT NULL,
        PRIMARY KEY(bot, persona, admission_ref),
        UNIQUE(bot, persona, operation_id, effect_id)
    )""")
    db.execute(
        "INSERT INTO graph_dispatch_admissions(bot,persona,admission_ref,"
        "operation_id,effect_id,admission_digest,admission_json,graph_revision,"
        "graph_epoch,receipt_digest) VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("bot", "persona", admission.admission_ref, admission.operation_id,
         admission.effect_id, admission.digest, json.dumps(asdict(admission)),
         2, 3, digest),
    )
    assert load_request(db, NamespaceId("bot", "persona"), "admission:one") is None
    install_schema(db)
    assert load_admission(db, NamespaceId("bot", "persona"), "admission:one") == receipt
    assert load_request(db, NamespaceId("bot", "persona"), "admission:one") is None
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


def _issuer_case(tmp_path, *, with_projection=False,
                 boundary_effect="allow", conflicting_allow=False,
                 astrbot_route=False, astrbot_scene_override=None,
                 astrbot_platform_name_override=None):
    namespace = (astrbot_namespace("platform-1", "bot-1", "persona")
                 if astrbot_route else NamespaceId("bot", "persona"))
    bot, persona = namespace.as_tuple
    audience = (json.dumps(["platform-1:FriendMessage:123456", "conversation-1"],
                           separators=(",", ":"))
                if astrbot_route else "entity:user")
    platform_ref = json.dumps(["platform-1", "aiocqhttp", "bot-1"],
                              separators=(",", ":"))
    scene_ref = (
        astrbot_scene_override or scene_ref_for_conversation(
            namespace, platform_ref, audience)
        if astrbot_route else "scene:one"
    )
    if with_projection:
        registry, providers = _registry()
        for provider in (ContextProvider(), RelationshipProvider()):
            for spec in provider.type_specs():
                registry.register(spec)
        store = GraphStore(tmp_path / "candidate.db", registry)
        seed = object()
        seed_coordinator = GraphCoordinator(
            store, seed, d02_issuer=_Resources(), d11_issuer=_Budget())
        for kind, version in (("scheme", "scheme-1"), ("operator", "operator-1"),
                              ("policy", "policy-1"), ("activation", 1)):
            seed_coordinator.set_guard_version(seed, namespace, kind, "current", version)
        with store._lock:
            create_budget_lease(store._db, BudgetLease(
                "parent", None, bot, persona, "USD", {"cpu_ms": 10},
                {}, {}, {}, 1, "active"), "install-parent", "0" * 64)
        MemoryRepository(store, bot, persona).ingest(
            Event(Scope(bot, persona, "session"), "source-ingress", 1.0, "ingress", {}),
            SourceRecord("source-1", "Hello", "alice", "observed", "confirmed",
                         1.0, 2.0, "family-1", (audience,), ("expression",)),
        )
        source_ref = source_key(bot, persona, "source-1").token
        role = RoleBinding(
            "binding:test", "persona:persona", "role:test", "entity:user", None,
            scene_ref, scene_ref, "private", ("norm:test",), 0.0, None,
            1, (source_ref,), 1, "active",
        )
        boundary = BoundaryRule(
            "boundary:test", "persona:persona", "entity:user", "message",
            audience, scene_ref,
            "allow" if boundary_effect == "none" else boundary_effect,
            "runtime_policy", (source_ref,),
            (), (), 0.0, None, 1, "owner", (), "active",
        )
        writes = [
            GraphWrite(AtomKey(Owner("scene", bot, persona, scene_ref),
                               "d03.role_binding", role.role_binding_id), _json(asdict(role))),
        ]
        if boundary_effect != "none":
            writes.append(GraphWrite(
                AtomKey(Owner("relation", bot, persona, "entity:user"),
                        "d05.boundary_rule", boundary.rule_id), _json(asdict(boundary))))
        if conflicting_allow:
            second = replace(boundary, rule_id="boundary:second")
            writes.append(GraphWrite(
                AtomKey(Owner("relation", bot, persona, "entity:user"),
                        "d05.boundary_rule", second.rule_id), _json(asdict(second))))
        writes = tuple(writes)
        epoch = GraphStore.graph_epoch(
            store, bot, persona,
            _capability=seed_coordinator._GraphCoordinator__graph_capability)
        GraphStore.graph_commit(
            store, GraphCandidate(
                Event(Scope(bot, persona, "test-domain-seed"),
                      "seed-current-projections", 2.0, "domain_seed", {}),
                tuple(GraphVersion(write.key, 0) for write in writes), writes, (epoch,),
            ), _capability=seed_coordinator._GraphCoordinator__graph_capability,
        )
    else:
        store, _old, _authority, _lease, providers, _registry_unused = _ready(tmp_path)
    bootstrap = object()
    issuer = _TestAdmissionIssuer()
    issuer.namespace = namespace
    issuer.audience = audience
    issuer.astrbot_route = astrbot_route
    issuer.platform_name_override = astrbot_platform_name_override
    budget = _ClockBudget()
    issuer.budget = budget
    coordinator = GraphCoordinator(
        store, bootstrap, d02_issuer=_Resources(), d11_issuer=budget,
        dispatch_admission_issuer=issuer,
    )
    for domain, provider in zip(("d06", "d08", "d09"), providers):
        coordinator.register_provider(
            bootstrap, domain, provider,
            "d06.contract.v1" if domain == "d06" else f"{domain}.proposal.v1",
            provider.descriptor.request_schema_hash,
        )
    if with_projection:
        for domain, provider in (("d03", ContextProvider()),
                                 ("d05", RelationshipProvider())):
            coordinator.register_provider(
                bootstrap, domain, provider, f"{domain}.proposal.v1",
                provider.descriptor.request_schema_hash,
            )
    coordinator.register_provider(
        bootstrap, "d11", D11RuntimeProvider(),
        D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH,
    )
    lease, capability = coordinator.grant(
        bootstrap, actor="host", issuer_domain="d06", namespace=namespace,
        domains=("d06", "d08", "d09", "d11", "d03", "d05")
        if with_projection else ("d06", "d08", "d09", "d11"),
        activation_generation=1,
    )
    from sylanne3.runtime_contracts import AuthorityContext

    authority = AuthorityContext(
        "host", "d06", capability, namespace,
        ("event", "activity", "scene", "relation") if with_projection
        else ("event", "activity"),
        "expression", (audience,), "policy-1", 1,
    )
    bundle, values = _qualified_bundle(
        coordinator, authority, lease, providers,
        projection_keys=tuple(write.key for write in writes) if with_projection else (),
        scene_ref=scene_ref,
    )
    issuer.bind(values)
    return store, coordinator, authority, lease, bundle, issuer


def test_issuer_without_current_d03_scene_binding_cannot_persist_admission(tmp_path):
    """A test issuer cannot turn an unbound scene into dispatch admission."""
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(tmp_path)
    namespace = authority.namespace
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    with pytest.raises(UnavailableGuard, match="current D03 scene binding"):
        coordinator._commit_domain_bundle_fenced(
            bundle, lease, dispatch_clock_reading=reading,
        )
    assert issuer.last_now_utc >= reading.utc_upper_bound_seconds
    assert issuer.budget.last_now_utc >= reading.utc_upper_bound_seconds
    assert issuer.last_now_utc >= issuer.budget.last_now_utc
    with store._lock:
        row = store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone()
        assert row is None
        assert load_admission(store._db, namespace, "admission:one") is None
    store.close()
    reopened = sqlite3.connect(tmp_path / "candidate.db")
    try:
        assert load_admission(reopened, namespace, "admission:one") is None
    finally:
        reopened.close()


@pytest.mark.parametrize("boundary_effect", ("allow", "none"))
def test_current_d03_d05_projection_preserves_admission_transaction_test(
        tmp_path, boundary_effect):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True, boundary_effect=boundary_effect)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    committed = coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading)
    assert committed.status == "committed"
    assert issuer.last_now_utc >= reading.utc_upper_bound_seconds
    assert issuer.budget.last_now_utc >= reading.utc_upper_bound_seconds
    with store._lock:
        row = store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone()
        assert row is not None
        assert json.loads(row[0])["dispatch_admission"]["ref"] == "admission:one"
        stored = load_admission(store._db, authority.namespace, "admission:one")
    assert stored is not None and stored.admission == issuer.admission
    assert stored.graph_epoch == committed.invalidated_epochs[0].revision
    assert coordinator.get_committed_dispatch_request(
        authority, lease, "admission:one") == issuer.request
    # The fixture admission uses abstract account/destination strings. It
    # proves D11 persistence, but cannot authorize an AstrBot UMO route.
    with pytest.raises(UnavailableGuard, match="route"):
        coordinator.get_dispatch_text_segment(authority, lease, issuer.request)
    with pytest.raises(UnavailableGuard, match="admission differs"):
        coordinator.get_dispatch_text_segment(
            authority, lease, replace(issuer.request, payload_ref="d09:wrong"))
    store.close()
    reopened = sqlite3.connect(tmp_path / "candidate.db")
    try:
        assert load_admission(reopened, authority.namespace, "admission:one") == stored
        assert load_request(reopened, authority.namespace, "admission:one") == (
            stored, issuer.request)
    finally:
        reopened.close()


def test_committed_request_rejects_same_id_changed_command_and_graph_receipt(tmp_path):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    assert coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading).status == "committed"
    assert coordinator.get_committed_dispatch_request(
        authority, lease, "admission:one") == issuer.request
    changed = replace(issuer.request, worker_fence=issuer.request.worker_fence + 1)
    with store._lock:
        store._db.execute(
            "UPDATE graph_dispatch_admissions SET request_json=? WHERE admission_ref=?",
            (json.dumps(asdict(changed), sort_keys=True, separators=(",", ":")),
             "admission:one"),
        )
    with pytest.raises(ValueError, match="request identity differs"):
        coordinator.get_committed_dispatch_request(authority, lease, "admission:one")
    with store._lock:
        store._db.execute(
            "UPDATE graph_dispatch_admissions SET request_json=? WHERE admission_ref=?",
            (json.dumps(asdict(issuer.request), sort_keys=True, separators=(",", ":")),
             "admission:one"),
        )
        row = store._db.execute(
            "SELECT receipt_json FROM graph_bundle_operations WHERE operation_id=?",
            (issuer.request.operation_id,),
        ).fetchone()
        graph_receipt = json.loads(row[0])
        graph_receipt["dispatch_admission"]["digest"] = "f" * 64
        store._db.execute(
            "UPDATE graph_bundle_operations SET receipt_json=? WHERE operation_id=?",
            (json.dumps(graph_receipt), issuer.request.operation_id),
        )
    with pytest.raises(UnavailableGuard, match="graph receipt"):
        coordinator.get_committed_dispatch_request(authority, lease, "admission:one")
    store.close()


def test_committed_astrbot_text_segment_uses_exact_batch_and_route(tmp_path):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True, astrbot_route=True)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    assert coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading).status == "committed"
    segment = coordinator.get_dispatch_text_segment(authority, lease, issuer.request)
    assert segment.body == "Hello"
    assert segment.media_refs == ()
    assert segment.claim_uses == (
        ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT),)
    assert (segment.platform_id, segment.platform_name, segment.self_id,
            segment.umo, segment.conversation_id, segment.scene_ref) == (
        "platform-1", "aiocqhttp", "bot-1",
        "platform-1:FriendMessage:123456", "conversation-1",
        issuer.admission.scene_ref)
    with pytest.raises(UnavailableGuard, match="admission differs"):
        coordinator.get_dispatch_text_segment(
            authority, lease, replace(issuer.request, segment_index=1,
                                      segment_count=2))
    store.close()


@pytest.mark.parametrize(
    ("scene_override", "platform_name_override"),
    (("scene:arbitrary-same-platform", None), (None, "wrong-platform-name")),
)
def test_committed_astrbot_text_rejects_unbound_same_platform_scene(
        tmp_path, scene_override, platform_name_override):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True, astrbot_route=True,
        astrbot_scene_override=scene_override,
        astrbot_platform_name_override=platform_name_override)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    assert coordinator._commit_domain_bundle_fenced(
        bundle, lease, dispatch_clock_reading=reading).status == "committed"
    with pytest.raises(UnavailableGuard, match="scene differs"):
        coordinator.get_dispatch_text_segment(authority, lease, issuer.request)
    store.close()


@pytest.mark.parametrize("wrong_part", ("batch", "index"))
def test_same_digest_cannot_admit_a_different_d09_payload_ref(tmp_path, wrong_part):
    store, coordinator, authority, lease, bundle, issuer = _issuer_case(
        tmp_path, with_projection=True)
    batch_ref = next(
        write.key.token
        for proposal in bundle.proposals for write in proposal.typed_writes
        if write.key.type_name == "d09.verified_segment_batch.v1"
    )
    if wrong_part == "batch":
        key = AtomKey.from_token(batch_ref)
        batch_ref = AtomKey(key.owner, key.type_name, key.name + "-other").token
        index = 0
    else:
        index = 1
    issuer.payload_ref_override = dispatch_segment_payload_ref(batch_ref, index)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    with pytest.raises(UnavailableGuard, match="payload reference differs"):
        coordinator._commit_domain_bundle_fenced(
            bundle, lease, dispatch_clock_reading=reading)
    assert issuer.request.payload_digest == issuer.batch["segments"][0]["payload_digest"]
    with store._lock:
        assert store._db.execute(
            "SELECT 1 FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
        assert load_admission(store._db, authority.namespace, "admission:one") is None
    store.close()


@pytest.mark.parametrize(
    ("boundary_effect", "conflicting_allow"),
    (("deny", False), ("allow", True)),
)
def test_current_d05_boundary_veto_rolls_back_admission(
        tmp_path, boundary_effect, conflicting_allow):
    store, coordinator, authority, lease, bundle, _issuer = _issuer_case(
        tmp_path, with_projection=True, boundary_effect=boundary_effect,
        conflicting_allow=conflicting_allow)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic - 0.01, monotonic, time.time() + 0.2,
    )
    with pytest.raises(UnavailableGuard, match="D05 boundary vetoed"):
        coordinator._commit_domain_bundle_fenced(
            bundle, lease, dispatch_clock_reading=reading)
    with store._lock:
        assert load_admission(store._db, authority.namespace, "admission:one") is None
        assert store._db.execute(
            "SELECT 1 FROM graph_bundle_operations WHERE operation_id=?",
            (bundle.envelope.identity.operation_id,),
        ).fetchone() is None
    store.close()


def test_unqualified_dispatch_clock_rolls_back_graph_and_budget(tmp_path):
    store, coordinator, authority, lease, bundle, _issuer = _issuer_case(tmp_path)
    monotonic = time.monotonic()
    reading = VerifiedIngressClockV2(
        IngressClockSampleV2("authority:test", "installation:test", "clock:test",
                             time.time(), monotonic, "epoch:test", 0.1),
        monotonic, monotonic + 100, time.time() + 0.2,
    )
    with pytest.raises(UnavailableGuard, match="paired dispatch admission clock"):
        coordinator._commit_domain_bundle_fenced(
            bundle, lease, dispatch_clock_reading=reading,
        )
    with store._lock:
        assert store._db.execute("SELECT 1 FROM graph_bundle_operations").fetchone() is None
        assert store._db.execute("SELECT 1 FROM runtime_budget_reservations").fetchone() is None
    store.close()


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
