import tempfile
import unittest
from pathlib import Path
import hashlib

from sylanne3.dispatch_runtime import (
    AdmissionAuthorityDescriptor,
    BusinessDispatchClaim,
    BusinessOperation,
    CurrentDispatchPermit,
    DispatchBlocked,
    DispatchRequest,
    DispatchRuntime,
    DispatchSettlement,
    DispatchUnavailable,
    HandoffStartReceipt,
    HandoffUncertain,
    PlatformCapabilityDescriptor,
    PlatformObservation,
    RecoveryDecision,
    RecoveryGateDescriptor,
)
from sylanne3.runtime_journal import (
    BudgetConstraint,
    ExecutionJournal,
    QuotaOccupancy,
    RecoveryConstraintFootprint,
)


def _footprint(*, effect_id="effect-1", segment_id=None, proactive=True):
    contact = segment_id is not None
    return RecoveryConstraintFootprint(
        namespace="bot/persona",
        activity_id="activity-1",
        effect_id=effect_id,
        external_idempotency_ref=f"provider-key:{effect_id}",
        external_query_ref=f"provider-query:{effect_id}",
        conflict_keys=("recipient:user-7",),
        communication_action="communication-1" if contact else None,
        contact_id="contact-1" if contact else None,
        segment_id=segment_id,
        object_gate_keys=("no-response:user-7",) if contact and proactive else (),
        quota_occupancies=(QuotaOccupancy("proactive-contact", "2026-W39", 1),)
        if contact and proactive else (),
        budgets=(BudgetConstraint("parent-budget-1", "0", "1", "5"),),
    )


def _digest(label):
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request(*, operation_id="operation-1", effect_id="effect-1", segment_id=None,
             segment_index=None, content_fence="content-fence-4", proactive=True):
    contact = segment_id is not None
    return DispatchRequest(
        namespace="bot/persona",
        operation_id=operation_id,
        activity_id="activity-1",
        effect_id=effect_id,
        attempt_id="attempt-1",
        command_digest=_digest(f"command:{effect_id}"),
        payload_ref=f"payload:{effect_id}",
        payload_digest=_digest(f"payload:{effect_id}"),
        platform_capability_ref="platform-capability:test",
        required_check_refs=(
            "check:d03", "check:d05", "check:d06", "check:d08", "check:d11",
        ) + (("check:d10",) if contact and proactive else ()),
        dispatch_generation=7,
        activation_generation=11,
        worker_fence=3,
        content_fence=content_fence,
        cancel_epoch=2,
        footprint=_footprint(effect_id=effect_id, segment_id=segment_id, proactive=proactive),
        proactive_contact=contact and proactive,
        segment_authorization_ref="segment-auth-1" if contact else None,
        segment_manifest_digest=_digest("segments:fixed") if contact else None,
        segment_index=segment_index,
        segment_count=3 if contact else None,
        contact_policy_check_ref="check:d10" if contact and proactive else None,
    )


class RecordingJournal:
    def __init__(self, journal, events):
        self.journal = journal
        self.events = events
        self.fail_claimed = False
        self.claimed_ref = None

    def prepare(self, **kwargs):
        self.events.append("journal.prepare")
        return self.journal.prepare(**kwargs)

    def observe(self, effect_id, command_digest, phase, observation_ref):
        self.events.append(f"journal.observe:{phase}")
        if phase == "claimed" and self.fail_claimed:
            raise OSError("claimed journal append failed")
        entry = self.journal.observe(effect_id, command_digest, phase, observation_ref)
        if phase == "claimed":
            self.claimed_ref = entry.observation_ref
        return entry

    def latest_execution_seq(self):
        return self.journal.latest_execution_seq()


class FakeAuthority:
    descriptor = AdmissionAuthorityDescriptor("authority:test", "sylanne.runtime.v1")

    def __init__(self, events):
        self.events = events
        self.operations = {}
        self.omit_check = None
        self.stale_content_fence = False
        self.stale_handoff_start = False
        self.fail_handoff_start = False
        self.fail_settlement = False
        self.settlement_status_override = None
        self.release_calls = 0
        self.revalidate_calls = 0

    def lookup_operation(self, namespace, operation_id):
        self.events.append("lookup")
        return self.operations.get(operation_id, BusinessOperation.absent(operation_id))

    def claim(self, request):
        self.events.append("claim")
        checks = tuple(ref for ref in request.required_check_refs if ref != self.omit_check)
        contact_id = request.footprint.contact_id
        segment_id = request.footprint.segment_id
        claim = BusinessDispatchClaim(
            admission_ref=f"admission:{request.operation_id}",
            dispatch_id=f"dispatch:{request.effect_id}",
            operation_id=request.operation_id,
            effect_id=request.effect_id,
            command_digest=request.command_digest,
            payload_digest=request.payload_digest,
            platform_capability_ref=request.platform_capability_ref,
            verified_check_refs=checks,
            dispatch_generation=request.dispatch_generation,
            activation_generation=request.activation_generation,
            worker_fence=request.worker_fence,
            content_fence=request.content_fence,
            cancel_epoch=request.cancel_epoch,
            contact_id=contact_id,
            segment_id=segment_id,
            proactive_contact=request.proactive_contact,
            contact_occupancy_ref=f"occupancy:{contact_id}" if request.proactive_contact else None,
            segment_authorization_ref=request.segment_authorization_ref,
            segment_manifest_digest=request.segment_manifest_digest,
            segment_index=request.segment_index,
            segment_count=request.segment_count,
        )
        self.operations[request.operation_id] = BusinessOperation(
            "claimed", request.operation_id, request.effect_id, request.command_digest,
            claim.admission_ref, None, None,
        )
        return claim

    def revalidate(self, claim, request):
        self.events.append("revalidate")
        self.revalidate_calls += 1
        return CurrentDispatchPermit(
            permit_ref=f"permit:{request.effect_id}",
            admission_ref=claim.admission_ref,
            dispatch_id=claim.dispatch_id,
            operation_id=request.operation_id,
            effect_id=request.effect_id,
            command_digest=request.command_digest,
            payload_digest=request.payload_digest,
            platform_capability_ref=request.platform_capability_ref,
            verified_check_refs=request.required_check_refs,
            dispatch_generation=request.dispatch_generation,
            activation_generation=request.activation_generation,
            worker_fence=request.worker_fence,
            content_fence="content-fence:stale" if self.stale_content_fence else request.content_fence,
            cancel_epoch=request.cancel_epoch,
            contact_id=request.footprint.contact_id,
            segment_id=request.footprint.segment_id,
            proactive_contact=request.proactive_contact,
            contact_occupancy_ref=claim.contact_occupancy_ref,
            segment_authorization_ref=request.segment_authorization_ref,
            segment_manifest_digest=request.segment_manifest_digest,
            segment_index=request.segment_index,
            segment_count=request.segment_count,
            expires_at_monotonic=100.0,
        )

    def begin_handoff(self, permit, request):
        self.events.append("begin_handoff")
        if self.fail_handoff_start:
            raise RuntimeError("handoff start unavailable")
        return HandoffStartReceipt(
            start_ref=f"handoff-start:{request.effect_id}",
            permit_ref=permit.permit_ref,
            operation_id=request.operation_id,
            effect_id=request.effect_id,
            platform_capability_ref=request.platform_capability_ref,
            dispatch_generation=request.dispatch_generation,
            activation_generation=request.activation_generation,
            worker_fence=request.worker_fence + 1 if self.stale_handoff_start else request.worker_fence,
            content_fence=request.content_fence,
            cancel_epoch=request.cancel_epoch,
            proactive_contact=request.proactive_contact,
            segment_authorization_ref=request.segment_authorization_ref,
            segment_manifest_digest=request.segment_manifest_digest,
            segment_index=request.segment_index,
            segment_count=request.segment_count,
        )

    def settle(self, claim, observation):
        self.events.append("settle")
        if self.fail_settlement:
            raise RuntimeError("business settlement unavailable")
        status = self.settlement_status_override or (
            "unknown" if observation.status == "unknown" else "settled"
        )
        receipt = DispatchSettlement(status, f"settlement:{claim.effect_id}")
        operation_status = "settled" if status == "settled" else "unknown"
        self.operations[claim.operation_id] = BusinessOperation(
            operation_status, claim.operation_id, claim.effect_id, claim.command_digest,
            claim.admission_ref, observation.observation_ref, receipt.settlement_ref,
        )
        return receipt

    def settle_existing(self, operation, observation):
        self.events.append("settle_existing")
        if self.fail_settlement:
            raise RuntimeError("business settlement unavailable")
        status = self.settlement_status_override or (
            "unknown" if observation.status == "unknown" else "settled"
        )
        receipt = DispatchSettlement(status, f"settlement:{operation.effect_id}")
        operation_status = "settled" if status == "settled" else "unknown"
        self.operations[operation.operation_id] = BusinessOperation(
            operation_status, operation.operation_id, operation.effect_id, operation.command_digest,
            operation.admission_ref, observation.observation_ref, receipt.settlement_ref,
        )
        return receipt

    def release_contact(self, contact_id):
        self.release_calls += 1


class FakePlatform:
    def __init__(self, events):
        self.events = events
        self.descriptor = PlatformCapabilityDescriptor(
            "platform-capability:test", "provider:test", True, True, True,
        )
        self.handoff_count = 0
        self.query_count = 0
        self.next_handoff = PlatformObservation("accepted", "provider:accepted-1", "provider-request-1")
        self.next_query = PlatformObservation("unknown", "provider:query-unknown-1", "provider-request-1")

    def handoff(self, request, start_receipt):
        self.events.append("handoff")
        self.handoff_count += 1
        if isinstance(self.next_handoff, BaseException):
            raise self.next_handoff
        return self.next_handoff

    def query_original(self, request, operation):
        self.events.append("query_original")
        self.query_count += 1
        if isinstance(self.next_query, BaseException):
            raise self.next_query
        return self.next_query


class FakeRecoveryGate:
    descriptor = RecoveryGateDescriptor("recovery-gate:test", "sylanne.runtime.v1")

    def __init__(self, events):
        self.events = events
        self.decisions = {}

    def check_current(self, request):
        self.events.append("recovery_check")
        return self.decisions.get(
            request.effect_id,
            RecoveryDecision(
                "clear", request.effect_id, request.command_digest,
                request.activation_generation, request.content_fence,
                f"recovery-proof:{request.effect_id}", None,
            ),
        )


class DispatchRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.events = []
        self.raw_journal = ExecutionJournal(Path(self.temp.name) / "execution.db")
        self.journal = RecordingJournal(self.raw_journal, self.events)
        self.authority = FakeAuthority(self.events)
        self.platform = FakePlatform(self.events)
        self.recovery = FakeRecoveryGate(self.events)
        self.runtime = DispatchRuntime(
            self.journal, self.authority, self.platform, self.recovery,
            monotonic_clock=lambda: 10.0,
        )

    def tearDown(self):
        self.raw_journal.close()
        self.temp.cleanup()

    def test_requires_explicit_business_authority_and_platform_capability(self):
        with self.assertRaises(DispatchUnavailable):
            DispatchRuntime(self.journal, None, self.platform, self.recovery)
        with self.assertRaises(DispatchUnavailable):
            DispatchRuntime(self.journal, self.authority, None, self.recovery)
        with self.assertRaises(DispatchUnavailable):
            DispatchRuntime(self.journal, self.authority, self.platform, None)
        with self.assertRaises(DispatchBlocked):
            self.runtime.dispatch(DispatchRequest(**{
                **_request().__dict__, "platform_capability_ref": "platform-capability:other",
            }))
        unverifying = FakePlatform(self.events)
        unverifying.descriptor = PlatformCapabilityDescriptor(
            "platform-capability:test", "provider:test", True, True, False,
        )
        with self.assertRaises(DispatchUnavailable):
            DispatchRuntime(self.journal, self.authority, unverifying, self.recovery)

    def test_command_and_payload_bindings_require_real_sha256_digests(self):
        with self.assertRaises(ValueError):
            DispatchRequest(**{**_request().__dict__, "payload_digest": "sha256:not-a-digest"})
        with self.assertRaises(ValueError):
            BusinessOperation(
                "settled", "operation-1", "effect-1", _digest("command:effect-1"),
                "admission-1", None, None,
            )

    def test_missing_required_check_in_claim_fails_before_journal_or_handoff(self):
        self.authority.omit_check = "check:d06"
        with self.assertRaises(DispatchBlocked):
            self.runtime.dispatch(_request())
        self.assertEqual(self.raw_journal.latest_execution_seq(), 0)
        self.assertEqual(self.platform.handoff_count, 0)

    def test_dispatch_order_claims_durably_before_current_fences_and_handoff(self):
        result = self.runtime.dispatch(_request())
        self.assertEqual(result.status, "accepted")
        self.assertEqual(
            self.events,
            [
                "recovery_check", "lookup", "claim", "journal.prepare",
                "journal.observe:claimed", "revalidate", "begin_handoff", "handoff",
                "journal.observe:acknowledged", "settle",
            ],
        )
        self.assertEqual(self.journal.claimed_ref, "admission:operation-1")
        self.assertEqual(self.platform.handoff_count, 1)

    def test_claimed_append_failure_never_consumes_start_or_calls_platform(self):
        self.journal.fail_claimed = True
        with self.assertRaisesRegex(OSError, "claimed journal append failed"):
            self.runtime.dispatch(_request())
        self.assertEqual(self.raw_journal.latest_execution_seq(), 1)
        self.assertNotIn("revalidate", self.events)
        self.assertNotIn("begin_handoff", self.events)
        self.assertEqual(self.platform.handoff_count, 0)

    def test_failed_handoff_start_keeps_original_effect_pending_without_resend(self):
        self.authority.fail_handoff_start = True
        with self.assertRaisesRegex(RuntimeError, "handoff start unavailable"):
            self.runtime.dispatch(_request())
        self.assertEqual(self.raw_journal.latest_execution_seq(), 2)
        self.assertEqual(self.platform.handoff_count, 0)
        self.authority.fail_handoff_start = False
        result = self.runtime.dispatch(_request())
        self.assertEqual(result.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 0)
        self.assertEqual(self.platform.query_count, 1)

    def test_stale_content_fence_after_prepare_blocks_handoff(self):
        self.authority.stale_content_fence = True
        with self.assertRaises(DispatchBlocked):
            self.runtime.dispatch(_request())
        self.assertEqual(self.raw_journal.latest_execution_seq(), 2)
        self.assertEqual(self.platform.handoff_count, 0)

    def test_handoff_start_must_atomically_bind_the_current_fences(self):
        self.authority.stale_handoff_start = True
        with self.assertRaises(DispatchBlocked):
            self.runtime.dispatch(_request())
        self.assertEqual(self.platform.handoff_count, 0)
        self.assertIn("journal.observe:claimed", self.events)

    def test_uncertain_handoff_is_journaled_and_restart_queries_original_without_resend(self):
        self.platform.next_handoff = HandoffUncertain("provider:timeout-1")
        first = self.runtime.dispatch(_request())
        self.assertEqual(first.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 1)

        self.platform.next_query = PlatformObservation(
            "unknown", "provider:query-timeout-2", "provider-request-1"
        )
        second_runtime = DispatchRuntime(
            self.journal, self.authority, self.platform, self.recovery,
            monotonic_clock=lambda: 11.0,
        )
        second = second_runtime.dispatch(_request())
        self.assertEqual(second.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 1)
        self.assertEqual(self.platform.query_count, 1)
        self.assertIn("settle_existing", self.events)

    def test_old_business_backup_cannot_hide_unresolved_effect_and_cause_resend(self):
        request = _request()
        self.platform.next_handoff = HandoffUncertain("provider:timeout-1")
        self.runtime.dispatch(request)
        recovered = self.authority.operations[request.operation_id]
        self.authority.operations.clear()  # simulate an older business backup
        self.recovery.decisions[request.effect_id] = RecoveryDecision(
            "unresolved", request.effect_id, request.command_digest,
            request.activation_generation, request.content_fence,
            "recovery-proof:unresolved-effect-1", recovered,
        )
        self.platform.next_query = PlatformObservation(
            "unknown", "provider:still-unknown", "provider-request-1"
        )
        result = self.runtime.dispatch(request)
        self.assertEqual(result.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 1)
        self.assertEqual(self.platform.query_count, 1)

    def test_observation_survives_business_settlement_failure_and_is_not_resent(self):
        self.authority.fail_settlement = True
        first = self.runtime.dispatch(_request())
        self.assertEqual(first.status, "pending_confirmation")
        self.assertEqual(self.raw_journal.latest_execution_seq(), 3)
        self.assertEqual(self.platform.handoff_count, 1)

        self.authority.fail_settlement = False
        second = self.runtime.dispatch(_request())
        self.assertEqual(second.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 1)
        self.assertEqual(self.platform.query_count, 1)

    def test_untyped_platform_return_is_recorded_unknown_after_handoff_not_treated_as_no_effect(self):
        self.platform.next_handoff = object()
        result = self.runtime.dispatch(_request())
        self.assertEqual(result.status, "pending_confirmation")
        self.assertEqual(self.platform.handoff_count, 1)
        self.assertEqual(self.raw_journal.latest_execution_seq(), 3)
        self.assertIn("journal.observe:unknown", self.events)

    def test_business_settlement_failure_never_reports_platform_acceptance_as_settled(self):
        self.authority.settlement_status_override = "failed"
        result = self.runtime.dispatch(_request())
        self.assertEqual(result.status, "pending_confirmation")
        self.assertEqual(result.observation_ref, "provider:accepted-1")

    def test_each_segment_revalidates_and_contact_occupancy_is_never_released(self):
        first = _request(operation_id="operation-segment-1", effect_id="effect-segment-1",
                         segment_id="segment-1", segment_index=0)
        second = _request(operation_id="operation-segment-2", effect_id="effect-segment-2",
                          segment_id="segment-2", segment_index=1)
        self.runtime.dispatch(first)
        self.runtime.dispatch(second)
        self.assertEqual(self.authority.revalidate_calls, 2)
        self.assertEqual(self.platform.handoff_count, 2)
        self.assertEqual(self.authority.release_calls, 0)

        self.authority.stale_content_fence = True
        third = _request(operation_id="operation-segment-3", effect_id="effect-segment-3",
                         segment_id="segment-3", segment_index=2)
        with self.assertRaises(DispatchBlocked):
            self.runtime.dispatch(third)
        self.assertEqual(self.platform.handoff_count, 2)
        self.assertEqual(self.authority.release_calls, 0)

    def test_responsive_multisegment_contact_does_not_invent_proactive_quota_or_d10_check(self):
        request = _request(
            operation_id="operation-response-1", effect_id="effect-response-1",
            segment_id="segment-response-1", segment_index=0, proactive=False,
        )
        result = self.runtime.dispatch(request)
        self.assertEqual(result.status, "accepted")
        self.assertNotIn("check:d10", request.required_check_refs)
        self.assertEqual(request.footprint.quota_occupancies, ())

    def test_contact_requires_finite_segment_authorization_and_d10_check(self):
        request = _request(operation_id="operation-segment-1", effect_id="effect-segment-1",
                           segment_id="segment-1", segment_index=0)
        with self.assertRaises(ValueError):
            DispatchRequest(**{**request.__dict__, "segment_count": None})
        with self.assertRaises(ValueError):
            DispatchRequest(**{
                **request.__dict__,
                "required_check_refs": tuple(
                    ref for ref in request.required_check_refs if ref != "check:d10"
                ),
            })
        with self.assertRaises(ValueError):
            DispatchRequest(**{**request.__dict__, "segment_count": 4})


if __name__ == "__main__":
    unittest.main()
