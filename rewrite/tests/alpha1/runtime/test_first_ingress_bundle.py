from dataclasses import replace
import hashlib
import unittest

from sylanne3.domains.d06 import D06DomainAdapter, SourceAdmission
from sylanne3.graph_types import GraphVersion
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.d11_types import runtime_job_key, runtime_outbox_key
from sylanne3.runtime.first_ingress_bundle import build_first_ingress_bundle
from sylanne3.runtime.jobs import PersistentJob
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, VersionGuard, VersionedRef, canonical_digest,
)


class FirstIngressBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = NamespaceId("bot-1", "persona-1")
        self.admission = SourceAdmission(
            "a" * 64, "hello", "sender-1", "reported", "reported",
            "reported_claim", "not_applicable", 10.0, 11.0,
            "platform-1", ("conversation-1",), ("context", "consolidation"),
        )
        self.source_identity = hashlib.sha256(
            ("sylanne3.host-ingress.v1:" + self.admission.source_id).encode("ascii")
        ).hexdigest()
        self.activity_id = "ingress-" + self.source_identity[:24]
        self.operation_id = "host-ingress-" + self.source_identity[:32]
        self.job_id = "encode-" + self.source_identity[:24]
        self.outbox_id = "encode-outbox-" + self.source_identity[:24]
        self.job_key = runtime_job_key(*self.namespace.as_tuple, self.activity_id, self.job_id)
        self.outbox_key = runtime_outbox_key(
            *self.namespace.as_tuple, self.activity_id, self.outbox_id
        )
        candidate = D06DomainAdapter(self.namespace).admit_source(self.admission)
        self.command = CommandEnvelope(
            RUNTIME_SCHEMA,
            OperationIdentity(
                self.activity_id, None, "attempt-1", "ingress", self.operation_id,
                canonical_digest({"input_refs": list(candidate.qualification.source_refs)}),
            ),
            AuthorityContext(
                "astrbot-host", "d06", "capability-1", self.namespace,
                ("event", "activity"), "context", ("conversation-1",),
                "ingress-policy-v1", 7,
            ),
            VersionGuard(
                tuple(GraphVersion(key, 0) for key in (
                    source_key(*self.namespace.as_tuple, self.admission.source_id),
                    access_key(*self.namespace.as_tuple, self.admission.source_id),
                    self.job_key, self.outbox_key,
                )),
                (), 0, 0, "catalogue-1", "scheme-1", "operator-1", "policy-1",
                (), (), (VersionedRef("quote-1", 1),),
            ),
            candidate.qualification, candidate.qualification.source_refs,
            "budget-lease-1", 41.0, 41.0, "character-interval-1", ("message-1",),
        )
        self.job = PersistentJob(
            self.job_id, self.operation_id, self.activity_id, None,
            *self.namespace.as_tuple, "snapshot-1", "queued", "d06.encode_source",
            {}, None, "2099-01-01T00:00:00Z", "budget-lease-1", "resource-1",
            {"resource_quote": "quote-1:1"}, None, None, 0, 0, {}, None,
        )

    def build(self, command=None, job=None):
        return build_first_ingress_bundle(
            command or self.command, job or self.job, self.admission,
            source_identity=self.source_identity, payload_ref=self.admission.source_id,
            idempotency_key="host-ingress:" + self.source_identity,
        )

    def test_builds_canonical_d06_d11_bundle(self) -> None:
        bundle = self.build()
        self.assertEqual(tuple(p.domain for p in bundle.proposals), ("d06", "d11"))
        self.assertEqual(bundle.persistent_job_refs, (self.job_key.token,))
        self.assertEqual(bundle.outbox_refs, (self.outbox_key.token,))
        self.assertEqual(bundle.proposals[1].dependencies.current_invalidation,
                         (GraphVersion(self.job_key, 0),))
        self.assertEqual(bundle.digest, self.build().digest)

    def test_rejects_missing_proof_and_changed_job(self) -> None:
        guard = replace(
            self.command.version_guard,
            read_versions=self.command.version_guard.read_versions[:-1],
        )
        with self.assertRaisesRegex(ValueError, "complete revision-0"):
            self.build(command=replace(self.command, version_guard=guard))
        with self.assertRaisesRegex(ValueError, "D11 issuer job"):
            self.build(job=replace(self.job, work_kind="other"))

    def test_rejects_source_identity_drift(self) -> None:
        with self.assertRaisesRegex(ValueError, "source identity"):
            build_first_ingress_bundle(
                self.command, self.job, self.admission,
                source_identity="b" * 64, payload_ref=self.admission.source_id,
                idempotency_key="host-ingress:" + self.source_identity,
            )


if __name__ == "__main__":
    unittest.main()
