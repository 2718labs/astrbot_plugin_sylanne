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
    AdminD06FirstIngressC02Policy, AdminD06SourceCorrectionPolicy,
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
    D06_SOURCE_CORRECTION_WORK_KIND,
    d06_source_correction_quote_id,
    d04_baseline_quote_id,
    d03_self_identity_projection_quote_id,
    build_runtime_issuers,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.d03_self_identity_projection_identity import (
    d03_self_identity_projection_activity_id_v1,
    d03_self_identity_projection_operation_id_v1,
    d03_self_identity_projection_retry_operation_id_v2,
)
from sylanne3.memory_types import access_key
from sylanne3.domains.d06 import CorrectionRequest, D06DomainAdapter
from sylanne3.workbench_api.source_correction import SourceCorrectionRequestV1
from sylanne3.authority_service.v2_contract import FencePermitV2, to_wire
from sylanne3.runtime.restore_anchor import RestoreAnchor
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

    def test_d06_correction_uses_installed_price_existing_grant_and_one_job(self):
        operation = "a980d36b-1c02-4d21-94a5-0304f46b3091"
        source = AtomKey(Owner("event", "bot", "persona", "source-1"),
                         "memory.source", "record")
        target = AtomKey(Owner("event", "bot", "persona", "target-1"),
                         "memory.interpretation", "current")
        request = SourceCorrectionRequestV1(
            self.namespace, operation, "sha256:" + "a" * 64,
            "我当时在忙", (source.token,), (target.token,), 3, 2,
        )
        correction = D06DomainAdapter(self.namespace).correction_source_key(
            CorrectionRequest(operation, request.target_refs, request.source_refs,
                              request.statement, 3, 2))
        input_refs = (correction.token, source.token, target.token)
        envelope = replace(
            self.envelope,
            identity=OperationIdentity(
                "activity-1", None, "attempt-1", "source-correction", operation,
                canonical_digest({"input_refs": list(input_refs)})),
            authority=replace(self.envelope.authority, actor="owner-actor",
                              issuer_domain="d06", owner_scope=("event",),
                              purpose="context", audience=("owner",)),
            version_guard=replace(self.envelope.version_guard,
                                  access_epoch=3, delete_epoch=2,
                                  resource_lease_versions=()),
            source_qualification=replace(self.envelope.source_qualification,
                                         source_refs=(source.token,)),
            input_refs=input_refs,
        )
        policy = AdminD06SourceCorrectionPolicy(
            60.0, {"cpu_ms": 7}, "correction-snapshot", "correction-resource")
        now = envelope.deadline_utc - 30.0
        with self.assertRaisesRegex(IssuerAuthorityDenied, "grant is absent"):
            self.d11.issue_d06_source_correction_quote(
                self.db, envelope, policy, request,
                installation_id="installation-1", now_utc=now)
        grant = replace(self.grant(), allowed_work_kinds=(
            D06_SOURCE_CORRECTION_WORK_KIND,))
        self.d11.issue_budget_grant(self.db, grant)
        quote = self.d11.issue_d06_source_correction_quote(
            self.db, envelope, policy, request,
            installation_id="installation-1", now_utc=now)
        self.assertEqual(quote.quote_id, d06_source_correction_quote_id(
            self.namespace, operation))
        self.assertEqual(quote.ceiling, {"cpu_ms": 7})
        self.assertEqual(len(quote.outbox_refs), 1)
        self.assertIsNotNone(quote.graph_job_ref)
        self.assertEqual(self.d11.issue_d06_source_correction_quote(
            self.db, envelope, policy, request,
            installation_id="installation-1", now_utc=now), quote)
        guarded = replace(envelope, version_guard=replace(
            envelope.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
        admission = self.d11.admit_runtime(DomainBundle(
            guarded, (), (), (), (), (), ("correction-replay",),
            (quote.graph_job_ref,), quote.outbox_refs,
        ), self.db, now_utc=now)
        self.assertEqual(admission.budget.ceiling, {"cpu_ms": 7})
        self.assertEqual(len(admission.jobs), 1)
        self.assertEqual(admission.jobs[0].outbox_refs, quote.outbox_refs)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "request differs"):
            self.d11.issue_d06_source_correction_quote(
                self.db, envelope, policy, replace(
                    request, operation_id="66d3b8e3-8941-4e53-b25c-300d1fc70ea7"),
                installation_id="installation-1", now_utc=now)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "bound to this command"):
            self.d11._admission_state(replace(
                guarded, identity=replace(guarded.identity, activity_id="other-activity")),
                self.db, now_utc=now)
        with self.assertRaisesRegex(IssuerAuthorityDenied, "bound to this command"):
            self.d11._admission_state(replace(
                guarded, deadline_utc=guarded.deadline_utc - 1),
                self.db, now_utc=now)
        self.db.execute("UPDATE runtime_budget_leases SET currency='EUR' WHERE lease_id='parent'")
        with self.assertRaisesRegex(IssuerAuthorityDenied, "signed budget grant"):
            self.d11._admission_state(guarded, self.db, now_utc=now)
        self.db.execute("UPDATE runtime_budget_leases SET currency='USD' WHERE lease_id='parent'")
        changed_request = replace(request, statement="不同纠错文字")
        with self.assertRaisesRegex(IssuerAuthorityDenied, "replay differs"):
            self.d11.issue_d06_source_correction_quote(
                self.db, envelope, policy, changed_request,
                installation_id="installation-1", now_utc=now)
        self.db.execute("UPDATE runtime_d06_correction_quote_policies "
                        "SET policy_json=replace(policy_json,'\"cpu_ms\":7','\"cpu_ms\":8')")
        with self.assertRaisesRegex(IssuerAuthorityDenied, "signature is invalid"):
            self.d11.admit_runtime(DomainBundle(
                guarded, (), (), (), (), (), ("correction-replay",),
                (quote.graph_job_ref,), quote.outbox_refs,
            ), self.db, now_utc=now)

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
            input_refs=(source.token,), causation=("op-1",),
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
        with self.assertRaisesRegex(IssuerAuthorityDenied, "lineage is absent"):
            self.d11.issue_d03_self_identity_projection_quote(
                self.db, replace(envelope, identity=replace(
                    identity, operation_id="client-chosen")), policy,
                installation_id="installation-1", qualified_mapping=mapping,
                now_utc=now)
        self.db.execute("UPDATE graph_atoms SET revision=2 WHERE token=?",
                        (event.token,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "stale"):
            self.d11._admission_state(guarded, self.db, now_utc=now)
        self.db.execute("UPDATE graph_atoms SET revision=1 WHERE token=?",
                        (event.token,))
        retry_id = d03_self_identity_projection_retry_operation_id_v2(
            self.namespace, source.token, mapping.certification_ref, operation, 1)
        retry = replace(envelope, identity=replace(identity, operation_id=retry_id))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "lineage is absent"):
            self.d11.issue_d03_self_identity_projection_quote(
                self.db, retry, policy, installation_id="installation-1",
                qualified_mapping=mapping, now_utc=now)
        self.db.execute("CREATE TABLE graph_stage_retry_lineage_v1("
                        "bot TEXT, persona TEXT, stage TEXT, source_ref TEXT,"
                        "original_operation_id TEXT, operation_id TEXT,"
                        "previous_operation_id TEXT, retry_index INTEGER,"
                        "previous_bundle_digest TEXT, previous_attempt_id TEXT,"
                        "previous_rejection_digest TEXT)")
        self.db.execute("CREATE TABLE graph_bundle_intents_v2("
                        "bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,"
                        "fence_attempt_id TEXT, graph_revision INTEGER, graph_epoch INTEGER)")
        self.db.execute("CREATE TABLE graph_bundle_rejections_v2("
                        "bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,"
                        "status TEXT, permit_json TEXT, graph_revision INTEGER,"
                        "graph_epoch INTEGER, finish_request_id TEXT,"
                        "finish_request_digest TEXT)")
        self.db.execute("CREATE TABLE graph_bundle_operations("
                        "bot TEXT, persona TEXT, operation_id TEXT)")
        self.db.execute("CREATE TABLE graph_bundle_fences_v2("
                        "bot TEXT, persona TEXT, operation_id TEXT)")
        self.db.execute("CREATE TABLE graph_d03_self_projection_intents_v1("
                        "bot TEXT, persona TEXT, source_ref TEXT,"
                        "original_operation_id TEXT, operation_id TEXT,"
                        "bundle_digest TEXT)")
        digest = "f" * 64
        attempt = "graph-write-old"
        anchor = RestoreAnchor(
            authority_id="authority", namespace="opaque",
            activation_generation=1, deletion_journal_id="delete",
            deletion_seq=0, deletion_digest="genesis",
            execution_journal_id="execute", execution_seq=0,
            execution_digest="genesis", revocation_epoch=1, proof="proof")
        permit = FencePermitV2(
            "authority", "opaque", "subject", "host", 1, "write",
            attempt, "A" * 43, 1, 1, anchor)
        rejection = (
            digest, "rejected_no_commit",
            json.dumps(to_wire(permit), sort_keys=True, separators=(",", ":")),
            1, 1, "abort:" + attempt,
            "sha256:" + canonical_digest({
                "operation_id": attempt, "permit_token": permit.token,
                "action": "rejected_no_commit", "business_operation_id": operation,
                "bundle_digest": digest,
            }),
        )
        self.db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?)",
                        ("bot", "persona", operation, digest, attempt, 1, 1))
        self.db.execute("INSERT INTO graph_bundle_rejections_v2 VALUES(?,?,?,?,?,?,?,?,?,?)",
                        ("bot", "persona", operation, *rejection))
        self.db.execute("INSERT INTO graph_stage_retry_lineage_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        ("bot", "persona", "d03",
                         source.token, "op-1", retry_id, operation, 1,
                         digest, attempt, canonical_digest(list(rejection))))
        self.db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?)",
                        ("bot", "persona", retry_id, "e" * 64,
                         "graph-write-current", 1, 1))
        self.db.execute("INSERT INTO graph_d03_self_projection_intents_v1 "
                        "VALUES(?,?,?,?,?,?)",
                        ("bot", "persona", source.token, "op-1", retry_id,
                         "e" * 64))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "quote survived rollback"):
            self.d11.issue_d03_self_identity_projection_quote(
                self.db, retry, policy, installation_id="installation-1",
                qualified_mapping=mapping, now_utc=now)
        self.db.execute("DELETE FROM runtime_resource_quotes WHERE quote_id=?",
                        (quote.quote_id,))  # Emulate the failed business transaction rollback.
        retry_quote = self.d11.issue_d03_self_identity_projection_quote(
            self.db, retry, policy, installation_id="installation-1",
            qualified_mapping=mapping, now_utc=now)
        self.assertNotEqual(retry_quote.quote_id, quote.quote_id)
        self.assertEqual(retry_quote.operation_id, retry_id)
        guarded_retry = replace(retry, version_guard=replace(
            retry.version_guard,
            resource_lease_versions=(VersionedRef(retry_quote.quote_id, 1),)))
        self.assertEqual(self.d11._admission_state(
            guarded_retry, self.db, now_utc=now)[0], retry_quote)
        self.db.execute("UPDATE graph_d03_self_projection_intents_v1 "
                        "SET bundle_digest=?", ("0" * 64,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "current intent"):
            self.d11._admission_state(guarded_retry, self.db, now_utc=now)
        self.db.execute("UPDATE graph_d03_self_projection_intents_v1 "
                        "SET bundle_digest=?", ("e" * 64,))
        self.db.execute("UPDATE graph_stage_retry_lineage_v1 "
                        "SET previous_rejection_digest=?", ("0" * 64,))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "durably rejected"):
            self.d11._admission_state(guarded_retry, self.db, now_utc=now)
        self.db.execute("UPDATE graph_stage_retry_lineage_v1 "
                        "SET previous_rejection_digest=?",
                        (canonical_digest(list(rejection)),))
        self.db.execute("INSERT INTO runtime_budget_reservations "
                        "(lease_id,operation_id,digest,ceiling_json,state) "
                        "VALUES(?,?,?,?,?)",
                        ("parent", operation, "a" * 64, '{"cpu_ms":7}', "reserved"))
        with self.assertRaisesRegex(IssuerAuthorityDenied, "budget is unresolved"):
            self.d11._admission_state(guarded_retry, self.db, now_utc=now)


if __name__ == "__main__":
    unittest.main()
