"""Actual Core Contact measurements and original-effect accounting fences."""
from __future__ import annotations

from datetime import datetime
import json

from .contract import AuthorityUnavailable
from .contact_effect_accounting_contract_v1 import (
    ContactEffectPricingPolicyV1, ContactSenderMeasurementV1, ContactEffectMeasurementReceiptV1,
    SignedContactEffectBudgetOriginV1, ContactEffectCostFactV1,
    ContactEffectAccountingRequestV1, ContactEffectAccountingGrantV1,
    MEASUREMENT_SIGN, ORIGIN_SIGN, to_wire, from_wire, encoded_v1,
)
from .v2_contract import (MutationReceiptV2, PlatformObservationV2,
    canonical_digest as authority_digest)
from ..runtime_contracts import canonical_digest, canonical_serialize

MEASUREMENT_TABLE = "authority_contact_effect_measurements_v1"
MEASUREMENT_COLUMNS = ("authority_namespace", "installation_id", "effect_id", "measurement_id",
    "measurement_digest", "receipt_json", "receipt_digest", "signature")
MEASUREMENT_DDL = """CREATE TABLE IF NOT EXISTS authority_contact_effect_measurements_v1 (
    authority_namespace TEXT NOT NULL, installation_id TEXT NOT NULL, effect_id TEXT NOT NULL,
    measurement_id TEXT NOT NULL, measurement_digest TEXT NOT NULL, receipt_json TEXT NOT NULL,
    receipt_digest TEXT NOT NULL, signature TEXT NOT NULL,
    PRIMARY KEY(authority_namespace,installation_id,effect_id), UNIQUE(measurement_id)) STRICT"""
MEASUREMENT_TRIGGER_DDLS = tuple(
    "CREATE TRIGGER IF NOT EXISTS " + MEASUREMENT_TABLE + "_no_" + action.lower() +
    " BEFORE " + action + " ON " + MEASUREMENT_TABLE +
    " BEGIN SELECT RAISE(ABORT,'Contact measurement is immutable'); END" for action in ("UPDATE", "DELETE"))


def install_contact_effect_measurement_schema_v1(db):
    db.execute(MEASUREMENT_DDL)
    for ddl in MEASUREMENT_TRIGGER_DDLS: db.execute(ddl)


def verify_measurement_receipt_v1(receipt, resource_issuer):
    if type(receipt) is not ContactEffectMeasurementReceiptV1:
        raise AuthorityUnavailable("exact signed Contact measurement receipt required")
    if canonical_digest(receipt.material()) != receipt.receipt_digest:
        raise AuthorityUnavailable("Contact measurement receipt material changed")
    resource_issuer._signer.verify(MEASUREMENT_SIGN,
        canonical_serialize(receipt.material()), receipt.signature)
    return receipt


class InstalledContactEffectAccountingServiceV1:
    """The Core authenticates execution lineage; Sender reports its own measured event."""
    def __init__(self, *, p2_service, accounting, bundle, create=True):
        from .contact_p2_service_v1 import InstalledContactP2ServiceV1
        from .v2_accounting_service import AuthorityV2AccountingMaintenanceService
        from ..host.authority_profile import AdminInstallationBundle
        if (type(p2_service) is not InstalledContactP2ServiceV1
                or type(accounting) is not AuthorityV2AccountingMaintenanceService
                or type(bundle) is not AdminInstallationBundle
                or p2_service.policy.core is not accounting._fences.core
                or p2_service.policy.fences is not accounting._fences
                or p2_service.policy.namespace != bundle.installation_policy.namespace
                or p2_service.policy.installation_id != bundle.installation_policy.installation_id
                or accounting._holder != bundle.installation_policy.administrator_holder):
            raise AuthorityUnavailable("Contact accounting requires its exact installed Core composition")
        self.p2, self.accounting, self.bundle = p2_service, accounting, bundle
        self.core, self.fences, self.execution = p2_service.policy.core, accounting._fences, p2_service.execution
        self.issuer, self.resource_issuer = p2_service.issuer, p2_service.issuer._d02
        self.namespace, self.installation_id = self.fences.namespace, p2_service.policy.installation_id
        self.subject, self.holder = accounting._subject, accounting._holder
        if create:
            with self.core._tx() as db: install_contact_effect_measurement_schema_v1(db)

    def _require(self, credential, subject, action):
        if subject != self.subject:
            raise AuthorityUnavailable("Contact accounting requires its designated installed Host")
        self.core._require(credential, action, self.namespace, self.holder)

    def _origin(self, signed):
        if (type(signed) is not SignedContactEffectBudgetOriginV1
                or signed.origin.authority_namespace != self.namespace
                or signed.origin.installation_id != self.installation_id
                or signed.origin.namespace != self.p2.policy.namespace):
            raise AuthorityUnavailable("Contact original budget crossed its installed namespace")
        self.issuer._signer.verify(ORIGIN_SIGN, encoded_v1(signed.origin), signed.signature)
        return signed.origin

    def _measurement_locked(self, db, effect_id, selected_digest=None):
        row = db.execute("SELECT measurement_digest,receipt_json,receipt_digest,signature FROM " + MEASUREMENT_TABLE +
            " WHERE authority_namespace=? AND installation_id=? AND effect_id=?",
            (self.namespace, self.installation_id, effect_id)).fetchone()
        if row is None:
            if selected_digest is not None:
                raise AuthorityUnavailable("selected original Contact measurement is absent")
            return None
        result = from_wire(json.loads(row[1]), ContactEffectMeasurementReceiptV1)
        verify_measurement_receipt_v1(result, self.resource_issuer)
        if (result.measurement.digest, result.receipt_digest, result.signature) != (row[0], row[2], row[3]):
            raise AuthorityUnavailable("Contact measurement immutable row differs")
        if selected_digest is not None and result.receipt_digest != selected_digest:
            raise AuthorityUnavailable("Contact accounting changed its selected measurement")
        return result

    def record_measurement(self, *, credential, subject, origin, measurement, observation, claimed_receipt):
        self._require(credential, subject, "accounting")
        original = self._origin(origin)
        policy = original.pricing_policy
        if (type(measurement) is not ContactSenderMeasurementV1 or type(observation) is not PlatformObservationV2
                or type(claimed_receipt) is not MutationReceiptV2 or type(policy) is not ContactEffectPricingPolicyV1):
            raise AuthorityUnavailable("configured actual Contact Sender measurement required")
        m, binding = measurement, observation.binding
        if (m.namespace != self.p2.policy.namespace or m.installation_id != self.installation_id
                or m.effect_id != original.effect_id or m.operation_id != original.operation_id
                or m.admission_ref != original.admission_ref
                or m.policy_digest != policy.digest or m.adapter_ref != policy.adapter_ref
                or m.observation_id != observation.observation_id or m.observation_outcome != observation.outcome
                or m.observed_at_utc != observation.observed_at_utc
                or (m.operation_id, m.activity_id, m.effect_id, m.attempt_id, m.admission_ref, m.handoff_id) !=
                   (binding.operation_id, binding.origin.activity_id, binding.origin.effect_id,
                    binding.origin.attempt_id, binding.origin.admission_ref, observation.handoff_id)
                or m.binding_digest != authority_digest(binding).removeprefix("sha256:")
                or m.claim_digest != authority_digest(claimed_receipt).removeprefix("sha256:")
                or m.start_digest != observation.start_digest.removeprefix("sha256:")
                or binding.origin.proactive_contact is not True or binding.origin.permit.subject != subject):
            raise AuthorityUnavailable("Sender measurement differs from the once Contact call")
        at = datetime.fromisoformat(m.observed_at_utc.replace("Z", "+00:00")).timestamp()
        if not policy.valid_from_utc <= at < policy.valid_until_utc:
            raise AuthorityUnavailable("original Contact pricing policy was not effective at invocation")
        with self.fences._frozen() as (db, deletion, execution, _):
            self.accounting._require_closed_deletion_history()
            existing = self._measurement_locked(db, m.effect_id)
            if existing is not None:
                if existing.measurement != m or existing.policy != policy:
                    raise AuthorityUnavailable("Contact invocation measurement replay conflicts")
                return existing
            row = self.execution.fences.mutation_locked(db, claimed_receipt.pending.mutation_id)
            completed = None if row is None else self.execution._completed_result(row)
            if completed is None or completed[0] != claimed_receipt:
                raise AuthorityUnavailable("actual original Contact claim receipt is unavailable")
            self.execution._check_v2_observation_start_locked(db, observation, claimed_receipt, subject)
            # The real execution bridge validated the permanent once-start and actual Graph claim.
            start_row = db.execute("SELECT operation_id,namespace,subject,claim_digest,binding_digest,graph_claim_ref,permit "
                "FROM authority_execution_handoff_starts_v1 WHERE handoff_id=?", (m.handoff_id,)).fetchone()
            material = {"measurement": to_wire(m), "policy": to_wire(policy), "authority_id": self.core._id(db),
                "authority_namespace": self.namespace, "subject": subject,
                "handoff_original_digest": canonical_digest((start_row[:6], bytes(start_row[6]).hex())),
                "schema": "authority.contact-effect-measurement-receipt.v1"}
            receipt = ContactEffectMeasurementReceiptV1(m, policy, material["authority_id"], self.namespace, subject,
                material["handoff_original_digest"], canonical_digest(material),
                self.resource_issuer._signer.sign(MEASUREMENT_SIGN, canonical_serialize(material)))
            encoded = encoded_v1(receipt)
            db.execute("INSERT INTO " + MEASUREMENT_TABLE + " VALUES(?,?,?,?,?,?,?,?)",
                (self.namespace, self.installation_id, m.effect_id, m.measurement_id, m.digest,
                    encoded, receipt.receipt_digest, receipt.signature))
            return receipt

    def _fact_locked(self, db, signed_origin, observed_mutation_id, selected_measurement):
        origin = self._origin(signed_origin)
        row = self.execution.fences.mutation_locked(db, observed_mutation_id)
        completed = None if row is None else self.execution._completed_result(row)
        if completed is None:
            raise AuthorityUnavailable("actual observed Contact mutation is unavailable")
        receipt, _ = completed
        pending, observation = receipt.pending, receipt.pending.platform_observation
        if (pending.phase != "observed" or observation is None or pending.permit.subject != self.subject
                or pending.permit.holder != self.holder or pending.permit.namespace != self.namespace
                or pending.permit.effect_id != origin.effect_id or pending.permit.operation_id != origin.operation_id):
            raise AuthorityUnavailable("Contact accounting original effect or subject differs")
        self.execution._check_v2_observation_start_locked(db, observation, pending.claimed_receipt, self.subject)
        # A later observation may refine the effect, but it never creates another Sender invocation.
        measurement = (None if selected_measurement is None else
            self._measurement_locked(db, origin.effect_id, selected_measurement))
        binding = observation.binding
        if (binding.graph_namespace, binding.operation_id, binding.origin.effect_id,
                binding.origin.activity_id, binding.origin.attempt_id, binding.origin.admission_ref,
                binding.admission_receipt_digest) != ("/".join(origin.namespace.as_tuple), origin.operation_id,
                origin.effect_id, origin.activity_id, origin.attempt_id, origin.admission_ref,
                "sha256:" + origin.admission_receipt_digest):
            raise AuthorityUnavailable("observed Contact binding differs from signed budget origin")
        return ContactEffectCostFactV1(signed_origin, pending.mutation_id,
            authority_digest(receipt).removeprefix("sha256:"),
            authority_digest(binding).removeprefix("sha256:"), observation.handoff_id,
            authority_digest(observation).removeprefix("sha256:"), observation.outcome, measurement, True)

    def read_fact(self, *, credential, subject, origin):
        self._require(credential, subject, "accounting")
        actual = self._origin(origin)
        receipt = self.execution.read_current_observation_receipt_v1(
            credential=credential, subject=subject, effect_id=actual.effect_id)
        with self.fences._frozen() as (db, deletion, execution, _):
            self.accounting._require_closed_deletion_history()
            measured = self._measurement_locked(db, actual.effect_id)
            return self._fact_locked(db, origin, receipt.pending.mutation_id,
                None if measured is None else measured.receipt_digest)

    def _request(self, credential, subject, request):
        self._require(credential, subject, "accounting")
        if (type(request) is not ContactEffectAccountingRequestV1
                or request.expected_anchor.authority_id != self.bundle.installation_policy.expected_authority_id
                or request.expected_anchor.namespace != self.namespace):
            raise AuthorityUnavailable("exact installed Contact effect accounting request required")
        self._origin(request.origin)

    def _binding(self, request, fact):
        return "sha256:" + canonical_digest((request.schema, to_wire(request), fact.digest))

    def begin(self, *, credential, subject, request):
        self._request(credential, subject, request)
        with self.fences._frozen() as (db, deletion, execution, _):
            self.accounting._require_closed_deletion_history()
            anchor = self.fences._current_locked(db, deletion, execution, holder=self.holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor: raise AuthorityUnavailable("Contact accounting anchor changed")
            fact = self._fact_locked(db, request.origin, request.observed_mutation_id, request.measurement_receipt_digest)
            permit = self.fences.fences.begin_fence_locked(db, subject=self.subject, holder=self.holder,
                operation="accounting", current_anchor=anchor, operation_id=request.operation_id,
                command_digest=self._binding(request, fact))
            return ContactEffectAccountingGrantV1(permit, request.origin.origin.digest, fact.digest, request.origin.origin.effect_id)

    def validate(self, *, credential, subject, request, grant):
        self._request(credential, subject, request)
        if type(grant) is not ContactEffectAccountingGrantV1:
            raise AuthorityUnavailable("actual Contact accounting grant required")
        with self.fences._frozen() as (db, deletion, execution, _):
            self.accounting._require_closed_deletion_history()
            anchor = self.fences._current_locked(db, deletion, execution, holder=self.holder,
                generation=request.expected_anchor.activation_generation)
            fact = self._fact_locked(db, request.origin, request.observed_mutation_id, request.measurement_receipt_digest)
            if (anchor != request.expected_anchor or grant.origin_digest != request.origin.origin.digest
                    or grant.effect_id != request.origin.origin.effect_id or grant.fact_digest != fact.digest
                    or grant.permit.command_digest != self._binding(request, fact)
                    or grant.permit.operation_id != request.operation_id):
                raise AuthorityUnavailable("Contact accounting grant changed its original fact")
            self.fences.fences.validate_fence_locked(db, grant.permit, subject=self.subject, current_anchor=anchor)

    @staticmethod
    def _finish_identity(request, permit):
        return ("contact-effect-accounting-finish:" + canonical_digest((request.operation_id, permit.token)),
            "sha256:" + canonical_digest(("finish_contact_effect_accounting.v1", to_wire(request), permit.token)))

    def finish(self, *, credential, subject, request, grant):
        self.validate(credential=credential, subject=subject, request=request, grant=grant)
        with self.fences._frozen() as (db, deletion, execution, _):
            self.accounting._require_closed_deletion_history()
            anchor = self.fences._current_locked(db, deletion, execution, holder=self.holder,
                generation=request.expected_anchor.activation_generation)
            if anchor != request.expected_anchor: raise AuthorityUnavailable("Contact accounting finish anchor changed")
            request_id, request_digest = self._finish_identity(request, grant.permit)
            self.fences.fences.finish_fence_locked(db, grant.permit, subject=self.subject,
                current_anchor=anchor, request_id=request_id, request_digest=request_digest)

    def recover_finish(self, *, credential, subject, request):
        self._request(credential, subject, request)
        permit, state, pending = self.fences.fences.get_operation(request.operation_id,
            subject=self.subject, namespace=self.namespace)
        if permit.operation != "accounting" or pending is not None or permit.pinned_anchor != request.expected_anchor:
            raise AuthorityUnavailable("Contact accounting recovery identity differs")
        finish_id, finish_digest = self._finish_identity(request, permit)
        if state == "finished":
            with self.core._tx() as db:
                row = self.fences.fences._row(db, request.operation_id)
                if row is None or row[8:10] != (finish_id, finish_digest):
                    raise AuthorityUnavailable("Contact original accounting finish differs")
            return
        if state != "active": raise AuthorityUnavailable("Contact accounting attempt is unresolved")
        with self.fences._frozen() as (db, deletion, execution, _):
            fact = self._fact_locked(db, request.origin, request.observed_mutation_id, request.measurement_receipt_digest)
        self.finish(credential=credential, subject=subject, request=request,
            grant=ContactEffectAccountingGrantV1(permit, request.origin.origin.digest, fact.digest, request.origin.origin.effect_id))
