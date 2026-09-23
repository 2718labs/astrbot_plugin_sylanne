import dataclasses
import math
import unittest
from typing import runtime_checkable

from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, NamespaceEpoch, Owner
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CheckReceipt,
    CommandEnvelope,
    CommitReceipt,
    DependencySet,
    DomainBundle,
    DomainProposal,
    DomainProvider,
    NamespaceId,
    OperationIdentity,
    ProviderDescriptor,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    VersionedRef,
    canonical_digest,
    canonical_serialize,
    schema_hash,
)


def key(bot="bot", persona="persona", name="mood"):
    return AtomKey(Owner("persona", bot, persona), "state", name)


def identity(digest=None):
    return OperationIdentity(
        activity_id="activity-1",
        effect_id=None,
        attempt_id="attempt-1",
        phase="prepare",
        operation_id="operation-1",
        canonical_input_digest=(canonical_digest({"input_refs": ["input:1"]})
                                if digest is None else digest),
    )


def authority(namespace=None):
    return AuthorityContext(
        actor="host:user-1",
        issuer_domain="d11",
        capability_ref="capability:opaque",
        namespace=namespace or NamespaceId("bot", "persona"),
        owner_scope=("persona", "relation"),
        purpose="respond",
        audience=("user-1",),
        provider_policy_ref="policy:1",
        activation_generation=2,
        worker_fence=None,
    )


def guard(atom_key=None):
    atom_key = atom_key or key()
    return VersionGuard(
        read_versions=(GraphVersion(atom_key, 0),),
        query_epochs=(QueryEpoch(NamespaceId(atom_key.owner.bot, atom_key.owner.persona),
                                 "query:recent", 3),),
        access_epoch=4,
        delete_epoch=5,
        catalogue_version="catalogue:1",
        scheme_version="scheme:1",
        operator_version="operators:1",
        policy_version="policy:1",
        source_grant_refs=(VersionedRef("grant:1", 1),),
        focus_lease_versions=(VersionedRef("focus:1", 2),),
        resource_lease_versions=(VersionedRef("resource:1", 3),),
    )


def qualification(confidence=0.75):
    return SourceQualification(
        source_refs=("source:1",),
        source_family="observed",
        occurred_at=1.0,
        learned_at=2.0,
        content_reality="external_observation",
        evidence_eligibility="eligible",
        subjective_confidence=confidence,
        internal_activity_actuality="not_applicable",
    )


def envelope(namespace=None):
    return CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=identity(),
        authority=authority(namespace),
        version_guard=guard(key((namespace or NamespaceId("bot", "persona")).bot_id,
                                (namespace or NamespaceId("bot", "persona")).persona_id)),
        source_qualification=qualification(),
        input_refs=("input:1",),
        parent_budget_lease_ref="budget:root",
        deadline_utc=100.0,
        monotonic_deadline=50.0,
        character_interval_ref="character-time:1",
        causation=("operation:parent",),
    )


class RuntimeContractTests(unittest.TestCase):
    def test_namespace_and_graph_versions_are_strong_and_compatible(self):
        namespace = NamespaceId.from_key(key())
        self.assertEqual(namespace, NamespaceId("bot", "persona"))
        self.assertEqual(namespace.as_tuple, ("bot", "persona"))
        with self.assertRaises(ValueError):
            NamespaceId("", "persona")
        with self.assertRaises(ValueError):
            dataclasses.replace(guard(), read_versions=(GraphVersion(key(), 0),
                                                        GraphVersion(key("other", "persona"), 0)))

    def test_contracts_are_frozen_and_reject_invalid_ids_versions_and_numbers(self):
        op = identity()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            op.phase = "commit"
        for bad_digest in ("", "not-a-digest", "a" * 63, "g" * 64):
            with self.assertRaises(ValueError):
                identity(bad_digest)
        with self.assertRaises(ValueError):
            AuthorityContext(**{**dataclasses.asdict(authority()), "namespace": NamespaceId("bot", "persona"),
                                "activation_generation": True})
        with self.assertRaises(TypeError):
            dataclasses.replace(authority(), audience="user-1")
        for number in (math.nan, math.inf, -math.inf):
            with self.assertRaises(ValueError):
                qualification(number)

    def test_canonical_serialization_is_stable_detached_and_rejects_non_json_numbers(self):
        left = {"z": [2, 1], "a": {"x": 1}}
        right = {"a": {"x": 1}, "z": [2, 1]}
        self.assertEqual(canonical_serialize(left), canonical_serialize(right))
        self.assertEqual(canonical_digest(left), canonical_digest(right))
        self.assertEqual(schema_hash(left), schema_hash(right))
        self.assertRegex(schema_hash(left), r"^[0-9a-f]{64}$")
        with self.assertRaises(ValueError):
            canonical_serialize({"bad": float("nan")})
        with self.assertRaises(TypeError):
            canonical_serialize({"bad": object()})

    def test_envelope_rejects_unknown_schema_namespace_leaks_and_digest_mismatch(self):
        with self.assertRaises(ValueError):
            dataclasses.replace(envelope(), schema="sylanne.runtime.v2")
        with self.assertRaises(ValueError):
            dataclasses.replace(envelope(), identity=identity("0" * 64))
        other = NamespaceId("other", "persona")
        with self.assertRaises(ValueError):
            dataclasses.replace(envelope(), authority=authority(other))

    def test_source_dimensions_remain_separate_and_simulation_cannot_claim_external_fact(self):
        unknown = dataclasses.replace(qualification(), occurred_at=None,
                                      subjective_confidence=None)
        self.assertIsNone(unknown.occurred_at)
        self.assertIsNone(unknown.subjective_confidence)
        self.assertEqual(unknown.learned_at, 2.0)
        self.assertEqual(dataclasses.replace(unknown, content_reality="unknown").content_reality,
                         "unknown")
        with self.assertRaises(ValueError):
            dataclasses.replace(qualification(), source_family="simulated",
                                content_reality="external_observation")
        with self.assertRaises(ValueError):
            dataclasses.replace(qualification(), source_family="authored",
                                evidence_eligibility="eligible")

    def test_proposal_and_bundle_preserve_dependency_classes_and_one_namespace(self):
        atom_key = key()
        dependencies = DependencySet(
            current_invalidation=(GraphVersion(atom_key, 1),),
            historical_provenance=(GraphVersion(atom_key, 1),),
            associations=(GraphVersion(atom_key, 1),),
            numeric_coupling=(GraphVersion(atom_key, 1),),
        )
        proposal = DomainProposal(
            domain="d04",
            proposal_schema="d04.proposal.v1",
            proposal_schema_hash=schema_hash({"domain": "d04", "version": 1}),
            envelope=envelope(),
            typed_writes=(GraphWrite(atom_key, {"value": 1}),),
            dependencies=dependencies,
            contribution_keys=("contribution:1",),
            required_bundle_parts=("experience", "cost_settlement"),
        )
        bundle = DomainBundle(
            envelope=envelope(),
            proposals=(proposal,),
            experience_refs=("experience:1",),
            choice_refs=(),
            d02_settlement_refs=(),
            d11_cost_settlement_refs=("cost:1",),
            idempotency_keys=("consume:1",),
            persistent_job_refs=(),
            outbox_refs=("outbox:1",),
        )
        self.assertEqual(bundle.proposals, (proposal,))
        self.assertEqual(bundle.digest, canonical_digest(bundle))
        self.assertEqual(proposal.typed_writes[0].value, {"value": 1})
        other_proposal = dataclasses.replace(
            proposal, envelope=envelope(NamespaceId("other", "persona")),
            typed_writes=(), dependencies=DependencySet()
        )
        with self.assertRaises(ValueError):
            dataclasses.replace(bundle, proposals=(other_proposal,))
        different_operation = dataclasses.replace(
            proposal,
            envelope=dataclasses.replace(
                envelope(), identity=dataclasses.replace(identity(), operation_id="operation-2")
            ),
        )
        with self.assertRaises(ValueError):
            dataclasses.replace(bundle, proposals=(different_operation,))
        with self.assertRaises(ValueError):
            dataclasses.replace(proposal, required_bundle_parts=("unknown",))

    def test_receipts_represent_unknown_as_pending_confirmation_and_partial_never_passes(self):
        receipt = CommitReceipt(
            status="pending_confirmation",
            operation_id="operation-1",
            operation_digest=canonical_digest({"operation": 1}),
            activity_id="activity-1",
            effect_id=None,
            commit_seq=None,
            read_versions=(GraphVersion(key(), 0),),
            write_versions=(),
            invalidated_epochs=(NamespaceEpoch("bot", "persona", 3),),
            ledger_refs=(),
            outbox_refs=(),
        )
        self.assertIsNone(receipt.commit_seq)
        with self.assertRaises(ValueError):
            dataclasses.replace(receipt, status="unknown")
        with self.assertRaises(ValueError):
            CheckReceipt(
                check_kind="permission",
                subject_ref="subject:1",
                action_ref="action:1",
                purpose="respond",
                input_versions=(VersionedRef("policy", 1),),
                coverage="partial",
                result="pass",
                valid_until=10.0,
                issuer="d11",
            )

    def test_provider_descriptor_and_protocol_do_not_grant_domain_authority(self):
        descriptor = ProviderDescriptor(
            provider_id="provider:one",
            contract_version="sylanne.runtime.v1",
            request_schema_hash=schema_hash({"request": 1}),
            response_schema_hash=schema_hash({"response": 1}),
            owner_capabilities=("persona",),
            supported_modalities=("text",),
            supported_purposes=("respond",),
            supported_platforms=("astrbot",),
            timeout_mode="bounded",
            cancellation_mode="cooperative",
            idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed",
            health_capabilities=("probe",),
            recovery_capabilities=("query_operation",),
        )
        self.assertEqual(descriptor.owner_capabilities, ("persona",))
        self.assertTrue(getattr(DomainProvider, "_is_runtime_protocol", False))
        self.assertFalse(hasattr(descriptor, "can_write"))


if __name__ == "__main__":
    unittest.main()
