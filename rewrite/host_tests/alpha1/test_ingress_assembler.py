from __future__ import annotations

from dataclasses import replace
import time
import unittest

from sylanne3.domains.d06 import D06DomainAdapter, D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_types import GraphVersion
from sylanne3.host import (
    CanonicalIngressObservation,
    HostIngressEnvelope,
    IngressAuthoritySession,
    IngressObservationContext,
    IngressRuntimeAuthorization,
    LocalIngressAssembler,
    SourceLineage,
    source_admission_from_host,
)
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.d11_types import (
    D11RuntimeProvider,
    runtime_job_key,
    runtime_outbox_key,
)
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime.ingress_contracts import CommittedIngressReplay
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    CommitReceipt,
    NamespaceId,
    OperationIdentity,
    RUNTIME_SCHEMA,
    VersionGuard,
    VersionedRef,
    canonical_digest,
)


def host_envelope() -> HostIngressEnvelope:
    return HostIngressEnvelope(
        NamespaceId("bot-1", "persona-1"),
        "platform-1",
        "conversation-1",
        "sender-1",
        "message-1",
        "hello",
        10.0,
        11.0,
        "private",
        SourceLineage(
            "a" * 64, "reported", "platform-1", "external_report",
            "reported_claim",
        ),
    )


class Coordinator(GraphCoordinator):
    def __init__(self) -> None:
        pass


class Issuer:
    def __init__(self, *, incomplete: bool = False, deadline_offset: float = 0) -> None:
        self.incomplete = incomplete
        self.deadline_offset = deadline_offset
        self.authorize_calls = 0
        self.generation = 7

    async def begin_authority(self, host, operation_id, coordinator, bootstrap):
        self.begin_bootstrap = bootstrap
        return IngressAuthoritySession(
            AuthorityContext(
                "astrbot-host", "d06", "capability-1", host.namespace,
                ("event", "activity"), "context", (host.conversation_ref,),
                "ingress-policy-v1", self.generation,
            ),
            object(),
        )

    async def authorize(self, request, session, coordinator, bootstrap):
        self.authorize_calls += 1
        self.request = request
        self.bootstrap = bootstrap
        host = request.host
        source = source_key(*host.namespace.as_tuple, request.admission.source_id)
        access = access_key(*host.namespace.as_tuple, request.admission.source_id)
        job_key = runtime_job_key(
            *host.namespace.as_tuple, request.activity_id, request.job_id
        )
        outbox_key = runtime_outbox_key(
            *host.namespace.as_tuple, request.activity_id, request.outbox_id
        )
        keys = (source,) if self.incomplete else (source, access, job_key, outbox_key)
        identity = OperationIdentity(
            request.activity_id,
            None,
            "attempt-1",
            "ingress",
            request.operation_id,
            canonical_digest(
                {"input_refs": list(request.candidate.qualification.source_refs)}
            ),
        )
        command = CommandEnvelope(
            RUNTIME_SCHEMA,
            identity,
            session.authority,
            VersionGuard(
                tuple(GraphVersion(key, 0) for key in keys),
                (), 0, 0, "catalogue-1", "scheme-1", "operator-1", "policy-1",
                (), (), (VersionedRef("quote-1", 1),),
            ),
            request.candidate.qualification,
            request.candidate.qualification.source_refs,
            "budget-lease-1",
            request.host.learned_at + 30 + self.deadline_offset,
            request.host.learned_at + 30 + self.deadline_offset,
            "character-interval-1",
            (host.message_id,),
        )
        job = PersistentJob(
            request.job_id, request.operation_id, request.activity_id, None,
            *host.namespace.as_tuple, "snapshot-1", "queued",
            "d06.encode_source", {}, None, "2099-01-01T00:00:00Z",
            "budget-lease-1", "resource-1", {"resource_quote": "quote-1:1"},
            None, None, 0, 0, {}, None,
        )
        return IngressRuntimeAuthorization(command, session.lease, job)


class ObservationAuthority:
    def __init__(self) -> None:
        self.records = {}
        self.bundle_digests = {}

    async def lookup_committed(self, context, session, content_fingerprint):
        context.require_session(session)
        return None

    async def observe_first(self, context, session, content_fingerprint, learned_at):
        context.require_session(session)
        self.last_context = context
        self.last_session = session
        key = (context.namespace, context.operation_id)
        prior = self.records.get(key)
        if prior is not None:
            if prior.content_fingerprint != content_fingerprint:
                raise ValueError("operation content fingerprint changed")
            return prior
        observation = CanonicalIngressObservation(
            context.operation_id,
            content_fingerprint,
            learned_at,
            "durable:first:" + context.operation_id,
        )
        self.records[key] = observation
        return observation

    async def seal_bundle(self, context, session, observation, bundle_digest):
        context.require_session(session)
        if (
            context.operation_id != observation.operation_id
            or context.namespace != self.last_context.namespace
            or context.activation_generation != self.last_context.activation_generation
        ):
            raise ValueError("observation authority context changed")
        key = (context.namespace, context.operation_id)
        return self.bundle_digests.setdefault(key, bundle_digest)


class IngressAssemblerTests(unittest.IsolatedAsyncioTestCase):
    async def test_builds_atomic_source_access_job_outbox_and_idempotency(self) -> None:
        host = host_envelope()
        admission = source_admission_from_host(host)
        candidate = D06DomainAdapter(host.namespace).admit_source(admission)
        bootstrap = object()
        issuer = Issuer()
        observations = ObservationAuthority()

        prepared = await LocalIngressAssembler(
            bootstrap, issuer, observations
        ).assemble(
            host, admission, candidate, Coordinator()
        )

        self.assertIs(issuer.bootstrap, bootstrap)
        self.assertEqual(observations.last_context.namespace, host.namespace)
        self.assertEqual(observations.last_context.activation_generation, 7)
        self.assertIs(observations.last_session.lease, prepared.lease)
        self.assertEqual(issuer.request.payload_ref, host.lineage.source_ref)
        self.assertEqual(
            tuple(proposal.domain for proposal in prepared.bundle.proposals),
            ("d06", "d11"),
        )
        self.assertEqual(
            tuple(len(proposal.typed_writes) for proposal in prepared.bundle.proposals),
            (2, 2),
        )
        self.assertEqual(
            prepared.bundle.idempotency_keys, (issuer.request.idempotency_key,)
        )
        self.assertEqual(len(prepared.bundle.persistent_job_refs), 1)
        self.assertEqual(len(prepared.bundle.outbox_refs), 1)
        self.assertEqual(
            D06DomainProvider().validate(prepared.bundle.proposals[0], None),
            prepared.bundle.proposals[0],
        )
        self.assertEqual(
            D11RuntimeProvider().validate(prepared.bundle.proposals[1], None),
            prepared.bundle.proposals[1],
        )

    async def test_fails_closed_before_bundle_on_incomplete_revision_proof(self) -> None:
        host = host_envelope()
        admission = source_admission_from_host(host)
        candidate = D06DomainAdapter(host.namespace).admit_source(admission)

        with self.assertRaisesRegex(ValueError, "complete revision-0"):
            await LocalIngressAssembler(
                object(), Issuer(incomplete=True), ObservationAuthority()
            ).assemble(
                host, admission, candidate, Coordinator()
            )

    async def test_repeated_message_reuses_first_learned_at_and_bundle_digest(self) -> None:
        first = host_envelope()
        repeated = replace(first, learned_at=99.0)
        observations = ObservationAuthority()
        assembler = LocalIngressAssembler(object(), Issuer(), observations)

        first_admission = source_admission_from_host(first)
        first_candidate = D06DomainAdapter(first.namespace).admit_source(first_admission)
        repeated_admission = source_admission_from_host(repeated)
        repeated_candidate = D06DomainAdapter(repeated.namespace).admit_source(
            repeated_admission
        )
        first_bundle = await assembler.assemble(
            first, first_admission, first_candidate, Coordinator()
        )
        repeated_bundle = await assembler.assemble(
            repeated, repeated_admission, repeated_candidate, Coordinator()
        )

        self.assertEqual(first_bundle.bundle.digest, repeated_bundle.bundle.digest)
        self.assertEqual(
            repeated_bundle.bundle.envelope.source_qualification.learned_at,
            first.learned_at,
        )

    async def test_committed_replay_skips_expired_quote_and_new_issuance(self) -> None:
        host = host_envelope()
        admission = source_admission_from_host(host)
        candidate = D06DomainAdapter(host.namespace).admit_source(admission)

        class ReplayCoordinator(Coordinator):
            receipt = None

            def get_operation(self, authority, lease, operation_id):
                return self.receipt

        class ReplayObservations(ObservationAuthority):
            receipt = None

            async def lookup_committed(self, context, session, content_fingerprint):
                context.require_session(session)
                if self.receipt is None:
                    return None
                first = self.records[(context.namespace, context.operation_id)]
                if first.content_fingerprint != content_fingerprint:
                    raise ValueError("committed content fingerprint changed")
                return CommittedIngressReplay(self.receipt, first, session)

        issuer = Issuer()
        observations = ReplayObservations()
        coordinator = ReplayCoordinator()
        assembler = LocalIngressAssembler(object(), issuer, observations)
        first = await assembler.assemble(host, admission, candidate, coordinator)
        self.assertEqual(issuer.authorize_calls, 1)
        self.assertLess(first.bundle.envelope.deadline_utc, time.time())
        receipt = CommitReceipt(
            "committed", first.bundle.envelope.identity.operation_id,
            first.bundle.digest, first.bundle.envelope.identity.activity_id,
            None, 1, (), (), (), (), (),
        )
        coordinator.receipt = observations.receipt = receipt
        issuer.generation = 8
        issuer.deadline_offset = -10_000
        replay_host = replace(host, learned_at=99.0)
        replay_admission = source_admission_from_host(replay_host)
        replay_candidate = D06DomainAdapter(host.namespace).admit_source(
            replay_admission)
        replay = await assembler.assemble(
            replay_host, replay_admission, replay_candidate, coordinator)
        self.assertIsInstance(replay, CommittedIngressReplay)
        self.assertEqual(replay.receipt, receipt)
        self.assertEqual(replay.session.authority.activation_generation, 8)
        self.assertEqual(issuer.authorize_calls, 1)

        changed = replace(replay_host, text="changed")
        changed_admission = source_admission_from_host(changed)
        with self.assertRaisesRegex(ValueError, "fingerprint changed"):
            await assembler.assemble(
                changed, changed_admission,
                D06DomainAdapter(host.namespace).admit_source(changed_admission),
                coordinator,
            )
        self.assertEqual(issuer.authorize_calls, 1)

        observations.receipt = replace(receipt, operation_digest="f" * 64)
        with self.assertRaisesRegex(ValueError, "no current coordinator receipt"):
            await assembler.assemble(
                replay_host, replay_admission, replay_candidate, coordinator)
        self.assertEqual(issuer.authorize_calls, 1)

    async def test_same_message_identity_with_changed_content_is_rejected(self) -> None:
        first = host_envelope()
        changed = replace(first, text="changed", learned_at=12.0)
        observations = ObservationAuthority()
        assembler = LocalIngressAssembler(object(), Issuer(), observations)

        first_admission = source_admission_from_host(first)
        await assembler.assemble(
            first,
            first_admission,
            D06DomainAdapter(first.namespace).admit_source(first_admission),
            Coordinator(),
        )
        changed_admission = source_admission_from_host(changed)
        with self.assertRaisesRegex(ValueError, "fingerprint changed"):
            await assembler.assemble(
                changed,
                changed_admission,
                D06DomainAdapter(changed.namespace).admit_source(changed_admission),
                Coordinator(),
            )

    async def test_retry_with_fresh_deadline_is_rejected_before_coordinator(self) -> None:
        host = host_envelope()
        admission = source_admission_from_host(host)
        candidate = D06DomainAdapter(host.namespace).admit_source(admission)
        observations = ObservationAuthority()
        await LocalIngressAssembler(
            object(), Issuer(), observations
        ).assemble(host, admission, candidate, Coordinator())

        with self.assertRaisesRegex(ValueError, "changed the canonical ingress bundle"):
            await LocalIngressAssembler(
                object(), Issuer(deadline_offset=1), observations
            ).assemble(host, admission, candidate, Coordinator())

    def test_forged_capability_ref_cannot_bind_observation_session(self) -> None:
        host = host_envelope()
        authority = AuthorityContext(
            "host", "d06", "real-capability", host.namespace,
            ("event", "activity"), "context", (host.conversation_ref,),
            "policy", 3,
        )
        session = IngressAuthoritySession(authority, object())
        forged = IngressObservationContext(
            host.namespace, 3, "host", "forged-capability", "operation-1"
        )
        with self.assertRaisesRegex(ValueError, "differs from opaque authority session"):
            forged.require_session(session)

    async def test_authorize_cannot_replace_coordinator_lease(self) -> None:
        host = host_envelope()
        admission = source_admission_from_host(host)
        candidate = D06DomainAdapter(host.namespace).admit_source(admission)

        class LeaseSwappingIssuer(Issuer):
            async def authorize(self, request, session, coordinator, bootstrap):
                authorized = await super().authorize(
                    request, session, coordinator, bootstrap
                )
                return IngressRuntimeAuthorization(
                    authorized.envelope, object(), authorized.job
                )

        with self.assertRaisesRegex(ValueError, "changed coordinator lease"):
            await LocalIngressAssembler(
                object(), LeaseSwappingIssuer(), ObservationAuthority()
            ).assemble(host, admission, candidate, Coordinator())


if __name__ == "__main__":
    unittest.main()
