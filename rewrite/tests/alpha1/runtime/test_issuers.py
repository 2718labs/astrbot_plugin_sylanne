import sqlite3
import json
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, self_mapping_key, self_perspective_id,
    self_perspective_key,
)
from sylanne3.host.authority_profile import (
    AdminD03SelfIdentityProjectionPolicy, AdminD04EncodingBaselinePolicy,
    AdminD06FirstIngressC02Policy,
    _d03_projection_from_payload, _d04_baseline_from_payload,
    _policy_from_payload,
)
from sylanne3.runtime import install_schema as install_runtime_schema
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, reserve_budget
from sylanne3.runtime.d11_types import runtime_job_key, runtime_outbox_key
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant,
    D02ResourceIssuer,
    D11BudgetGrantIssuer,
    D11BudgetJobIssuer,
    IssuerAuthorityDenied,
    ResourceOutcome,
    ResourceQuote,
    D04_BASELINE_WORK_KIND,
    D03_SELF_IDENTITY_PROJECTION_WORK_KIND,
    D06_FIRST_INGRESS_C02_WORK_KIND,
    d04_baseline_quote_id,
    d03_self_identity_projection_quote_id,
    build_runtime_issuers,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.d03_self_identity_projection_identity import (
    d03_self_identity_projection_activity_id_v1,
    d03_self_identity_projection_operation_id_v1,
)
from sylanne3.memory_types import access_key
from sylanne3.runtime.jobs import create_job
from sylanne3.runtime_contracts import (
    RUNTIME_SCHEMA,
    AuthorityContext,
    CommandEnvelope,
    DomainBundle,
    NamespaceId,
    OperationIdentity,
    SourceQualification,
    VersionGuard,
    VersionedRef,
    canonical_digest,
)


class ProductionIssuerTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        install_runtime_schema(self.db)
        install_issuer_schema(self.db)
        self.d02, self.d11 = build_runtime_issuers(
            b"k" * 32,
            outcome_verifier=lambda outcome, quote, db: (
                outcome.provider_receipt_ref == "provider-receipt-1"
                and outcome.operation_id == quote.operation_id
            ),
        )
        self.namespace = NamespaceId("bot", "persona")
        self.job_ref = runtime_job_key(
            "bot", "persona", "activity-1", "job-1"
        ).token
        self.outbox_ref = runtime_outbox_key(
            "bot", "persona", "activity-1", "outbox-1"
        ).token
        self.envelope = self.make_envelope()
        create_budget_lease(
            self.db,
            BudgetLease(
                "parent", None, "bot", "persona", "USD",
                {"cpu_ms": 10_000, "model_microusd": 5_000},
                {}, {}, {}, 1, "active",
            ),
            "create-parent", "a" * 64,
        )

    def make_envelope(self, *, worker_fence=None, deadline=4_102_444_800.0):
        identity = OperationIdentity(
            "activity-1", None, "attempt-1", "run", "op-1",
            canonical_digest({"input_refs": []}),
        )
        authority = AuthorityContext(
            "worker-1", "d11", "capability-1", self.namespace,
            ("activity",), "consolidation", ("internal",), "policy-1", 1,
            worker_fence,
        )
        guard = VersionGuard(
            (), (), 0, 0, "catalogue-1", "scheme-1", "operator-1", "policy-1",
            (), (), (VersionedRef("quote-1", 1),),
        )
        source = SourceQualification(
            (), "reported", 1.0, 1.0, "external_report", "qualified", 0.5,
            "not_applicable",
        )
        return CommandEnvelope(
            RUNTIME_SCHEMA, identity, authority, guard, source, (), "parent",
            deadline, 100.0, "character-1", (),
        )

    def quote(self, *, ceiling=None, worker_fence=None,
              deadline=4_102_444_800.0, valid_until=4_102_444_900.0):
        return ResourceQuote(
            "quote-1", 1, "bot", "persona", "activity-1", "op-1", None,
            "parent", "encode", "snapshot-1", deadline,
            "resource-1", self.job_ref, (self.outbox_ref,), (),
            ceiling or {"cpu_ms": 200, "model_microusd": 300},
            worker_fence, valid_until,
        )

    def grant(self, *, max_ceiling=None):
        return BudgetLeaseGrant(
            "grant-1", 1, "bot", "persona", "parent", "USD",
            max_ceiling or {"cpu_ms": 1_000, "model_microusd": 1_000},
            ("encode",), 4_102_445_000.0, "policy-1",
        )

    def bundle(self, *, settle=False):
        return DomainBundle(
            self.envelope, (), (), (), (),
            ("cost-token",) if settle else (), ("idempotency-1",),
            (self.job_ref,), (self.outbox_ref,),
        )

    def issue_authorities(self, *, quote=None, grant=None):
        self.d02.issue_quote(self.db, quote or self.quote())
        self.d11.issue_budget_grant(self.db, grant or self.grant())

    def test_grant_issuer_signs_without_d02_and_rejects_tampering(self):
        issuer = D11BudgetGrantIssuer(b"k" * 32)
        grant = self.grant()
        signature = issuer.issue_budget_grant(self.db, grant)
        self.assertEqual(issuer.current_budget_grant(self.db, "parent"), grant)
        self.assertEqual(signature, self.db.execute(
            "SELECT signature FROM runtime_budget_grants WHERE lease_id='parent'"
        ).fetchone()[0])
        with self.assertRaises(IssuerAuthorityDenied):
            D11BudgetGrantIssuer(b"x" * 32).current_budget_grant(self.db, "parent")
        self.db.execute(
            "UPDATE runtime_budget_grants SET grant_json=replace(grant_json, '1000', '999') "
            "WHERE lease_id='parent'"
        )
        with self.assertRaises(IssuerAuthorityDenied):
            issuer.current_budget_grant(self.db, "parent")

    def test_missing_or_tampered_quote_fails_closed(self):
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)
        self.issue_authorities()
        self.assertTrue(self.d02.authorize_schedule(self.envelope, self.db))
        self.db.execute(
            "UPDATE runtime_resource_quotes SET quote_json=replace(quote_json,'200','1') "
            "WHERE quote_id='quote-1' AND version=1"
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)

    def test_schedule_admission_uses_signed_quote_ceiling_and_lease(self):
        self.issue_authorities()
        admission = self.d11.admit_schedule(self.envelope, self.db)
        self.assertEqual(admission.budget.ceiling,
                         {"cpu_ms": 200, "model_microusd": 300})
        self.assertEqual(admission.budget.lease_id, "parent")
        self.assertEqual(admission.job.job_id, "job-1")
        self.assertEqual(admission.job.resource_ref, "resource-1")
        with self.assertRaises(IssuerAuthorityDenied):
            other_d02, other_d11 = build_runtime_issuers(b"x" * 32)
            other_d11.admit_schedule(self.envelope, self.db)

    def test_quote_cannot_exceed_signed_budget_grant(self):
        self.issue_authorities(
            quote=self.quote(ceiling={"cpu_ms": 200}),
            grant=self.grant(max_ceiling={"cpu_ms": 100}),
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_schedule(self.envelope, self.db)

    def test_past_command_quote_and_grant_are_rejected_against_current_utc(self):
        past = time.time() - 60.0
        self.envelope = self.make_envelope(deadline=past)
        self.issue_authorities(
            quote=self.quote(deadline=past, valid_until=past + 10.0),
            grant=BudgetLeaseGrant(
                "grant-1", 1, "bot", "persona", "parent", "USD",
                {"cpu_ms": 1_000, "model_microusd": 1_000},
                ("encode",), past + 20.0, "policy-1",
            ),
        )
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_schedule(self.envelope, self.db)
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_schedule(self.envelope, self.db)

    def test_runtime_admission_uses_durable_reservation_job_and_signed_outcome(self):
        self.issue_authorities()
        schedule = self.d11.admit_schedule(self.envelope, self.db)
        digest = budget_operation_digest(
            self.envelope, "parent", schedule.budget.ceiling,
        )
        reserve_budget(self.db, "parent", "op-1", digest,
                       schedule.budget.ceiling)
        create_job(self.db, schedule.job, "create-job", digest)
        self.d02.issue_outcome(
            self.db,
            ResourceOutcome(
                "outcome-1", 1, "quote-1", "bot", "persona", "activity-1",
                "op-1", {"cpu_ms": 180, "model_microusd": 250}, True,
                "provider-receipt-1",
            ),
        )
        admission = self.d11.admit_runtime(self.bundle(settle=True), self.db)
        self.assertTrue(admission.budget.pre_reserved)
        self.assertTrue(admission.budget.settle_now)
        self.assertEqual(admission.budget.actual,
                         {"cpu_ms": 180, "model_microusd": 250})
        self.assertEqual(admission.budget.reservation_operation_id, "op-1")
        self.assertEqual(admission.jobs[0].job, schedule.job)
        self.assertEqual(admission.jobs[0].outbox_refs, (self.outbox_ref,))

    def test_settlement_without_signed_outcome_never_manufactures_zero_cost(self):
        self.issue_authorities()
        with self.assertRaises(IssuerAuthorityDenied):
            self.d11.admit_runtime(self.bundle(settle=True), self.db)

    def test_outcome_without_server_side_verifier_is_not_authority(self):
        unverified_d02, _ = build_runtime_issuers(b"z" * 32)
        unverified_d02.issue_quote(self.db, ResourceQuote(
            "quote-unverified", 1, "bot", "persona", "activity-1", "op-1", None,
            "parent", "encode", "snapshot-1", 4_102_444_800.0,
            "resource-1", self.job_ref, (), (), {"cpu_ms": 200}, None,
            4_102_444_900.0,
        ))
        with self.assertRaises(IssuerAuthorityDenied):
            unverified_d02.issue_outcome(
                self.db,
                ResourceOutcome(
                    "unverified", 1, "quote-unverified", "bot", "persona",
                    "activity-1", "op-1", {"cpu_ms": 1}, True,
                    "untrusted-receipt",
                ),
            )

    def test_worker_fence_is_bound_to_quote_and_durable_job(self):
        self.envelope = self.make_envelope(worker_fence=2)
        self.issue_authorities(quote=self.quote(worker_fence=1))
        with self.assertRaises(IssuerAuthorityDenied):
            self.d02.authorize_resources(self.bundle(), self.db)

    def test_d04_baseline_uses_own_installed_price_grant_and_committed_prerequisite(self):
        source = AtomKey(Owner("event", "bot", "persona", "source-event"),
                         "memory.source", "record")
        event = AtomKey(Owner("event", "bot", "persona", "arrival-event"),
                        "d03.world_event", "current")
        refs = (source.token, event.token)
        self.db.execute("CREATE TABLE graph_atoms(token TEXT PRIMARY KEY, revision INTEGER, valid INTEGER, value TEXT)")
        self.db.executemany("INSERT INTO graph_atoms VALUES(?,?,1,?)", (
            (source.token, 1, "{}"),
            (event.token, 2, json.dumps({
                "event_id": "arrival-event", "kind": "message_received",
                "reality": "host_observed", "source_refs": [source.token],
                "learned_at": 1.0,
            })),
        ))
        identity = replace(
            self.envelope.identity, phase="encoding_baseline", effect_id=None,
            canonical_input_digest=canonical_digest({"input_refs": list(refs)}),
        )
        envelope = replace(
            self.envelope, identity=identity,
            authority=replace(self.envelope.authority, actor="host",
                              owner_scope=("event",)),
            version_guard=replace(
                self.envelope.version_guard,
                read_versions=(GraphVersion(source, 1), GraphVersion(event, 2)),
                resource_lease_versions=(),
            ),
            source_qualification=replace(
                self.envelope.source_qualification, source_refs=(source.token,)),
            input_refs=refs,
        )
        policy = AdminD04EncodingBaselinePolicy(
            60.0, {"cpu_ms": 30}, "baseline-snapshot", "baseline-resource",
        )
        now = envelope.deadline_utc - 30.0
        d04_grant = replace(self.grant(),
                            allowed_work_kinds=(D04_BASELINE_WORK_KIND,))
        self.d11.issue_budget_grant(self.db, d04_grant)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "installed D04"):
            self.d11.issue_d04_baseline_quote(
                self.db, envelope, None, installation_id="installation-1", now_utc=now,
            )
        quote = self.d11.issue_d04_baseline_quote(
            self.db, envelope, policy, installation_id="installation-1", now_utc=now,
        )
        self.assertEqual(quote.work_kind, D04_BASELINE_WORK_KIND)
        self.assertEqual(quote.quote_id, d04_baseline_quote_id(self.namespace, "op-1"))
        self.assertEqual(quote.ceiling, {"cpu_ms": 30})
        self.assertEqual(self.d11.issue_d04_baseline_quote(
            self.db, envelope, policy, installation_id="installation-1", now_utc=now,
        ), quote)
        guarded = replace(envelope, version_guard=replace(
            envelope.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id, 1),),
        ))
        admitted, _, _ = self.d11._admission_state(guarded, self.db, now_utc=now)
        self.assertEqual(admitted, quote)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "policy binding"):
            self.d02.issue_quote(self.db, replace(
                quote, quote_id="unbound-d04", snapshot_ref="d06snap:unrelated",
            ))
            self.d11._admission_state(replace(guarded, version_guard=replace(
                guarded.version_guard,
                resource_lease_versions=(VersionedRef("unbound-d04", 1),),
            )), self.db, now_utc=now)
        self.db.execute("UPDATE graph_atoms SET revision=3 WHERE token=?", (event.token,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "prerequisite is not current"):
            self.d11.issue_d04_baseline_quote(
                self.db, envelope, policy, installation_id="installation-1", now_utc=now,
            )
        self.db.execute(
            "UPDATE graph_atoms SET revision=2, value=? WHERE token=?",
            (json.dumps({"event_id": "arrival-event", "kind": "message_received",
                         "reality": "host_observed", "source_refs": ["other-source"],
                         "learned_at": 1.0}), event.token),
        )
        with self.assertRaisesRegex(IssuerAuthorityDenied, "does not bind this source"):
            self.d11.issue_d04_baseline_quote(
                self.db, envelope, policy, installation_id="installation-1", now_utc=now,
            )
        self.db.execute("UPDATE runtime_d04_baseline_quote_policies "
                        "SET policy_json=replace(policy_json,'30','31')")
        with self.assertRaisesRegex(IssuerAuthorityDenied, "signature is invalid"):
            self.d11._admission_state(guarded, self.db, now_utc=now)

    def test_d04_profile_requires_explicit_policy_and_matching_root_kind(self):
        grant = replace(self.grant(),
                        allowed_work_kinds=(D04_BASELINE_WORK_KIND,))
        profile = {
            "schema": 2, "host": "authority.example", "port": 443,
            "server_name": "authority.example",
            "expected_authority_id": "authority",
            "installation_policy": {
                "namespace": {"bot_id": "bot", "persona_id": "persona"},
                "authority_namespace": "opaque",
                "installation_id": "installation-1",
                "manifest_digest": "a" * 64,
                "administrator_holder": "administrator",
                "expected_authority_id": "authority",
                "catalogue_hash": "b" * 64,
                "scheme_version": "scheme", "operator_version": "operator",
                "policy_version": "policy",
                "root_lease": {
                    "lease_id": "parent", "parent_id": None, "bot_id": "bot",
                    "persona_id": "persona", "currency": "USD",
                    "limits": {"cpu_ms": 10_000, "model_microusd": 5_000},
                    "used": {}, "reserved": {}, "unconfirmed": {},
                    "version": 1, "state": "active",
                },
                "root_grant": {
                    "grant_id": grant.grant_id, "version": grant.version,
                    "bot_id": grant.bot_id, "persona_id": grant.persona_id,
                    "lease_id": grant.lease_id, "currency": grant.currency,
                    "max_ceiling": dict(grant.max_ceiling),
                    "allowed_work_kinds": list(grant.allowed_work_kinds),
                    "valid_until_utc": grant.valid_until_utc,
                    "policy_ref": grant.policy_ref,
                },
            },
            "d04_encoding_baseline": {
                "deadline_after_seconds": 30.0,
                "quote_ceiling": {"cpu_ms": 30},
                "snapshot_ref": "baseline-snapshot",
                "resource_ref": "baseline-resource",
            },
        }
        self.assertEqual(_d04_baseline_from_payload(profile).quote_ceiling,
                         {"cpu_ms": 30})
        self.assertEqual(_policy_from_payload(profile).root_grant, grant)
        profile["d03_self_identity_projection"] = {
            "deadline_after_seconds": 30.0, "quote_ceiling": {"cpu_ms": 7},
            "snapshot_ref": "projection-snapshot",
            "resource_ref": "projection-resource",
        }
        self.assertEqual(_d03_projection_from_payload(profile).quote_ceiling,
                         {"cpu_ms": 7})
        with self.assertRaisesRegex(ValueError, "D03 projection requires an explicit"):
            _policy_from_payload(profile)
        profile["installation_policy"]["root_grant"]["allowed_work_kinds"] = [
            D04_BASELINE_WORK_KIND, D03_SELF_IDENTITY_PROJECTION_WORK_KIND,
        ]
        self.assertEqual(_policy_from_payload(profile).root_grant.allowed_work_kinds,
                         (D04_BASELINE_WORK_KIND,
                          D03_SELF_IDENTITY_PROJECTION_WORK_KIND))
        profile.pop("d03_self_identity_projection")
        profile["installation_policy"]["root_grant"]["allowed_work_kinds"] = [
            "d06.encode_source",
        ]
        with self.assertRaisesRegex(ValueError, "explicit root grant work kind"):
            _policy_from_payload(profile)
        profile.pop("d04_encoding_baseline")
        self.assertIsNone(_d04_baseline_from_payload(profile))

    def test_d06_c02_stage_has_own_signed_price_and_consumer_identity(self):
        source = AtomKey(Owner("event", "bot", "persona", "source-event"),
                         "memory.source", "record")
        event = AtomKey(Owner("event", "bot", "persona", "arrival-event"),
                        "d03.world_event", "current")
        baseline = AtomKey(source.owner, "d04.encoding_baseline.v1", "baseline")
        refs = (source.token, event.token, baseline.token)
        identity = replace(
            self.envelope.identity, phase="first_ingress_c02",
            operation_id="first-ingress-c02-consumer",
            canonical_input_digest=canonical_digest({"input_refs": list(refs)}),
        )
        envelope = replace(
            self.envelope, identity=identity,
            authority=replace(self.envelope.authority, issuer_domain="d06",
                              owner_scope=("event",), worker_fence=1),
            version_guard=replace(self.envelope.version_guard,
                read_versions=(GraphVersion(source, 1), GraphVersion(event, 1),
                               GraphVersion(baseline, 1)),
                resource_lease_versions=()),
            source_qualification=replace(
                self.envelope.source_qualification, source_refs=(source.token,)),
            input_refs=refs,
        )
        origin = SimpleNamespace(
            job_id="job-1", activity_id="activity-1", operation_id="op-1",
            acquire_operation_id="acquire-1", call_id="call-1",
            binding_digest="a" * 64, model_request_digest="b" * 64,
            cost_operation_id="model-cost-1", cost_receipt_digest="c" * 64,
            source_ref=source.token,
            consumer_operation_id=identity.operation_id,
            installation_id="installation-1",
        )
        grant = replace(self.grant(), allowed_work_kinds=(
            D06_FIRST_INGRESS_C02_WORK_KIND,))
        policy = AdminD06FirstIngressC02Policy(
            60.0, {"cpu_ms": 5}, "c02-snapshot", "c02-resource")
        now = envelope.deadline_utc - 30.0
        with patch("sylanne3.runtime.issuers._d06_c02_origin", return_value=origin):
            with self.assertRaisesRegex(IssuerAuthorityDenied, "grant is absent"):
                self.d11.issue_d06_first_ingress_c02_quote(
                    self.db, envelope, policy, installation_id="installation-1",
                    job_id="job-1", now_utc=now)
            self.d11.issue_budget_grant(self.db, grant)
            quote = self.d11.issue_d06_first_ingress_c02_quote(
                self.db, envelope, policy, installation_id="installation-1",
                job_id="job-1", now_utc=now)
            self.assertEqual(quote.work_kind, D06_FIRST_INGRESS_C02_WORK_KIND)
            self.assertEqual(quote.operation_id, origin.consumer_operation_id)
            self.assertEqual(quote.ceiling, {"cpu_ms": 5})
            self.assertIsNone(quote.graph_job_ref)
            self.assertEqual((quote.outbox_refs, quote.d02_settlement_refs), ((), ()))
            guarded = replace(envelope, version_guard=replace(
                envelope.version_guard,
                resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
            self.assertEqual(self.d11._admission_state(
                guarded, self.db, now_utc=now)[0], quote)
            with self.assertRaisesRegex(IssuerAuthorityDenied, "consumer"):
                self.d11.issue_d06_first_ingress_c02_quote(
                    self.db, replace(envelope, identity=replace(
                        identity, operation_id="client-chosen")), policy,
                    installation_id="installation-1", job_id="job-1", now_utc=now)
            self.db.execute("UPDATE runtime_d06_c02_quote_policies SET policy_json="
                            "replace(policy_json,'\"cpu_ms\":5','\"cpu_ms\":6')")
            with self.assertRaisesRegex(IssuerAuthorityDenied, "signature is invalid"):
                self.d11._admission_state(guarded, self.db, now_utc=now)

    def test_d06_c02_price_never_rebills_original_model(self):
        with self.assertRaisesRegex(ValueError, "already-settled model"):
            AdminD06FirstIngressC02Policy(
                60.0, {"output_tokens": 5}, "c02-snapshot", "c02-resource")

    def test_d03_self_projection_uses_distinct_signed_quote_and_mapping(self):
        source = AtomKey(Owner("event", "bot", "persona", "source-event"),
                         "memory.source", "record")
        access = access_key("bot", "persona", "source-event")
        event = AtomKey(Owner("event", "bot", "persona", "arrival-event"),
                        "d03.world_event", "current")
        mapping_key = self_mapping_key(self.namespace)
        perspective = self_perspective_key(self.namespace, self_perspective_id(
            self.namespace, "scene:test", event.token))
        mapping = SelfIdentityMapping(
            "self-map:1", "persona:persona", "entity:self",
            "authority:self-identity:stable", "head-1", "incarnation-1", "active")
        self.db.execute("CREATE TABLE graph_atoms(token TEXT PRIMARY KEY, "
                        "revision INTEGER, valid INTEGER, value TEXT)")
        self.db.executemany("INSERT INTO graph_atoms VALUES(?,?,1,?)", (
            (source.token, 1, "{}"), (access.token, 1, "{}"),
            (event.token, 1, json.dumps({
                "event_id": "arrival-event", "kind": "message_received",
                "reality": "host_observed", "scene_ref": "scene:test",
                "source_refs": [source.token],
            })),
        ))
        self.db.execute("CREATE TABLE graph_recovery_metadata_v2("
                        "bot TEXT, persona TEXT, requirements_json TEXT)")
        self.db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?)",
                        ("bot", "persona", json.dumps({
                            "graph_incarnation": "incarnation-1"})))
        operation = d03_self_identity_projection_operation_id_v1(
            self.namespace, source.token, mapping.certification_ref)
        identity = replace(
            self.envelope.identity,
            activity_id=d03_self_identity_projection_activity_id_v1(
                self.namespace, source.token),
            phase=D03_SELF_IDENTITY_PROJECTION_WORK_KIND,
            operation_id=operation,
            canonical_input_digest=canonical_digest({"input_refs": [source.token]}),
        )
        envelope = replace(
            self.envelope, identity=identity,
            authority=replace(self.envelope.authority, actor="host",
                              owner_scope=("persona", "event"), purpose="context"),
            version_guard=replace(self.envelope.version_guard,
                read_versions=(GraphVersion(source, 1), GraphVersion(access, 1),
                               GraphVersion(event, 1), GraphVersion(mapping_key, 0),
                               GraphVersion(perspective, 0)),
                resource_lease_versions=()),
            source_qualification=replace(
                self.envelope.source_qualification, source_refs=(source.token,)),
            input_refs=(source.token,),
        )
        policy = AdminD03SelfIdentityProjectionPolicy(
            60.0, {"cpu_ms": 7}, "projection-snapshot", "projection-resource")
        now = envelope.deadline_utc - 30.0
        grant = replace(self.grant(), allowed_work_kinds=(
            D03_SELF_IDENTITY_PROJECTION_WORK_KIND,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "grant is absent"):
            self.d11.issue_d03_self_identity_projection_quote(
                self.db, envelope, policy, installation_id="installation-1",
                qualified_mapping=mapping, now_utc=now)
        self.d11.issue_budget_grant(self.db, grant)
        quote = self.d11.issue_d03_self_identity_projection_quote(
            self.db, envelope, policy, installation_id="installation-1",
            qualified_mapping=mapping, now_utc=now)
        self.assertEqual(quote.work_kind, D03_SELF_IDENTITY_PROJECTION_WORK_KIND)
        self.assertEqual(quote.quote_id, d03_self_identity_projection_quote_id(
            self.namespace, operation))
        self.assertEqual(quote.ceiling, {"cpu_ms": 7})
        guarded = replace(envelope, version_guard=replace(
            envelope.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
        self.assertEqual(self.d11._admission_state(
            guarded, self.db, now_utc=now)[0], quote)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "mapping or operation"):
            self.d11.issue_d03_self_identity_projection_quote(
                self.db, replace(envelope, identity=replace(
                    identity, operation_id="client-chosen")), policy,
                installation_id="installation-1", qualified_mapping=mapping,
                now_utc=now)
        self.db.execute("UPDATE graph_atoms SET revision=2 WHERE token=?",
                        (event.token,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "stale"):
            self.d11._admission_state(guarded, self.db, now_utc=now)


if __name__ == "__main__":
    unittest.main()
