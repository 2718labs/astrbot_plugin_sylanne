"""C04 Authority adapter over one typed execution chain.

The same-chain journal substrate exists. Claim and terminal remain closed until
the installed service supplies W01's current prepared/quote/Owner reader and
the Core-CAS write ports. A separate side table or a dispatch-shaped fake is
never a substitute for those service-owned ports.

Same-chain journal contract (same DB, writer lock and append chain):

* ``append_internal_work_claim_v1(binding, claim, before_head)`` must durably
  append one typed claim and return an ``InternalWorkJournalAppendV1``. Replay
  of the same mutation ID returns that original append; a different binding
  with the ID is a conflict. It must never execute user code under the lock.
* ``append_internal_work_terminal_v1(binding, claim, terminal, before_head)``
  must require the exact preceding claim, append one terminal using the fixed
  mutation ID, reject conflicting terminal bytes, and preserve unknown CPU as
  NULL. It returns an ``InternalWorkJournalAppendV1``.
* ``read_internal_work_v1(binding)`` must freeze the writer, verify the entire
  mixed dispatch/internal-work chain, and return an
  ``InternalWorkJournalInspectionV1`` with original claim/terminal bytes and
  append receipts. Claim with no terminal is ``unknown`` with no actual cost.

The installed claim port must verify W01's immutable prepared original, quote,
budget and Owner head before the first append. The terminal port must verify
the executor's original measurement. Both pair each append with Core's head
CAS and reconcile a lost ACK before opening any restore anchor.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
from typing import Callable

from ..contracts import canonical_json
from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, JournalHead, identifier
from .internal_work_contract import (
    InternalWorkBindingV1, InternalWorkClaimV1,
    InternalWorkTerminalProofV1, InternalWorkTerminalV1, InternalWorkTerminalV2,
    claim_internal_work_v1, terminal_internal_work_v1,
    validate_internal_work_terminal_proof_v1,
)
from .v2_execution_journal import AuthorityV2ExecutionJournal


@dataclass(frozen=True, slots=True)
class InternalWorkJournalAppendV1:
    """One verified append identity returned by the installed journal only."""

    namespace: str
    journal_id: str
    sequence: int
    mutation_id: str
    binding_digest: str
    content_digest: str
    chain_digest: str
    receipt_ref: str


@dataclass(frozen=True, slots=True)
class InternalWorkJournalInspectionV1:
    """Full-chain reread result; None terminal after claim means unknown."""

    binding: InternalWorkBindingV1
    claim: InternalWorkClaimV1 | None
    terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2 | None
    claim_append: InternalWorkJournalAppendV1 | None
    terminal_append: InternalWorkJournalAppendV1 | None
    verified_head: JournalHead


@dataclass(frozen=True, slots=True)
class AuthorityInternalWorkVerifiedReceiptV1:
    """Authority-origin reread result for D02, never a caller-created permit."""

    proof_digest: str
    namespace: str
    activity_id: str
    operation_id: str
    execution_id: str
    input_digest: str
    resource_quote_ref: str
    resource_quote_version: int
    resource_quote_digest: str
    terminal_receipt_ref: str
    terminal_receipt_digest: str
    terminal_sequence: int
    journal_head: JournalHead
    status: str
    actual_cpu_ms: int | None
    component_completed: bool


class AuthorityInternalWorkService:
    """Narrow Authority seam; never reports success without same-chain ports."""

    def __init__(self, journal: AuthorityV2ExecutionJournal, *,
                 current_prepared_reader: Callable | None = None,
                 claim_port: Callable | None = None,
                 terminal_port: Callable | None = None,
                 core_head_verifier: Callable | None = None,
                 component_signing_key: bytes | None = None,
                 installed_build_digest: str | None = None,
                 installed_build_attestation: dict | None = None,
                 trusted_manifest_sha256: str | None = None,
                 original_reconciler: Callable | None = None):
        if type(journal) is not AuthorityV2ExecutionJournal:
            raise TypeError("installed execution journal required")
        self.journal = journal
        self._current_prepared_reader = current_prepared_reader
        self._claim_port = claim_port
        self._terminal_port = terminal_port
        self._core_head_verifier = core_head_verifier
        if original_reconciler is not None and not callable(original_reconciler):
            raise AuthorityUnavailable("installed C04 original reconciler is invalid")
        self._original_reconciler = original_reconciler
        if (component_signing_key is not None and
                (type(component_signing_key) is not bytes or
                 len(component_signing_key) < 32)):
            raise ValueError("installed component signing key needs 32 bytes")
        self._component_signing_key = component_signing_key
        if (installed_build_digest is not None and
                (type(installed_build_digest) is not str or
                 len(installed_build_digest) != 64 or
                 any(char not in "0123456789abcdef"
                     for char in installed_build_digest))):
            raise ValueError("installed manifest build digest differs")
        self.installed_build_digest = installed_build_digest
        self.formal_build_verified = False
        self.installed_runtime_verified = False
        self.installed_runtime_scope = None
        self.installed_algorithm_id = None
        if installed_build_attestation is not None:
            attestation = installed_build_attestation
            from ..host.installed_d06_build import ALGORITHM_ID, ALGORITHM_ID_V3

            if (type(attestation) is not dict or
                    type(trusted_manifest_sha256) is not str or
                    len(trusted_manifest_sha256) != 64 or
                    any(char not in "0123456789abcdef"
                        for char in trusted_manifest_sha256) or
                    attestation.get("schema") != "sylanne.d06.algorithm-build.v1" or
                    attestation.get("algorithm_id") not in
                    {ALGORITHM_ID, ALGORITHM_ID_V3} or
                    attestation.get("manifest_sha256") != trusted_manifest_sha256 or
                    attestation.get("build_digest") !=
                    "sha256:" + str(installed_build_digest)):
                raise ValueError("installed D06 build attestation differs")
            formal = (attestation.get("package_mode") == "formal-alpha1"
                      and attestation.get("status") == "formal_package_bytes_only")
            candidate = (
                attestation.get("package_mode") in {"backend-alpha1-candidate", "snapshot-alpha1-test"}
                and attestation.get("status") == "backend_acceptance_package_bytes_only"
                and attestation.get("runtime_scope") == "backend-production-acceptance"
            )
            if not formal and not candidate:
                raise ValueError("D06 diagnostics cannot obtain production runtime attestation")
            self.formal_build_verified = formal
            self.installed_runtime_verified = True
            self.installed_runtime_scope = ("formal-alpha1" if formal
                                            else "backend-production-acceptance")
            self.installed_algorithm_id = attestation["algorithm_id"]

    @staticmethod
    def _component_payload(binding: InternalWorkBindingV1,
                           terminal: InternalWorkTerminalV2) -> str:
        return canonical_json({
            "schema": "sylanne3.internal_work.component_completion.v2",
            "binding_digest": binding.binding_digest,
            "claim_mutation_id": terminal.claim_mutation_id,
            "component_id": binding.component_id,
            "algorithm_id": terminal.algorithm_id,
            "build_fingerprint": terminal.build_fingerprint,
            "input_digest": terminal.input_digest,
            "result_digest": terminal.result_digest,
            "output_json": terminal.output_json,
            "actual_cpu_ms": terminal.actual_cpu_ms,
            "component_receipt_ref": terminal.component_receipt_ref,
        })

    def sign_component_completion(self, binding: InternalWorkBindingV1,
                                  terminal: InternalWorkTerminalV2) -> tuple[str, str]:
        """Installed executor calls this after observed work, before terminal append."""
        if (not self.installed_runtime_verified or
                self._component_signing_key is None or
                terminal.status != "completed"):
            raise AuthorityUnavailable("installed component signer unavailable")
        payload = self._component_payload(binding, terminal).encode("utf-8")
        return (hashlib.sha256(payload).hexdigest(),
                hmac.new(self._component_signing_key, payload, hashlib.sha256).hexdigest())

    def _verified_component_completion(self, binding: InternalWorkBindingV1,
                                       terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2) -> bool:
        if (type(terminal) is not InternalWorkTerminalV2 or
                terminal.status != "completed" or
                not self.installed_runtime_verified or
                self._component_signing_key is None or
                binding.algorithm_ref != self.installed_algorithm_id or
                binding.algorithm_build_digest != self.installed_build_digest or
                terminal.algorithm_id != binding.algorithm_ref or
                terminal.build_fingerprint != binding.algorithm_build_digest or
                terminal.input_digest != binding.input_digest or
                terminal.component_receipt_ref !=
                "internal-work:component:" + binding.binding_digest):
            return False
        digest, signature = self.sign_component_completion(binding, terminal)
        return (hmac.compare_digest(digest, terminal.component_receipt_digest) and
                hmac.compare_digest(signature, terminal.component_receipt_signature))

    def sign_execution_terminal(self, terminal: InternalWorkTerminalV2) -> str:
        """Seal the installed executor's observed terminal, including failed CPU."""
        if (not self.installed_runtime_verified or
                self._component_signing_key is None or
                terminal.status == "unknown"):
            raise AuthorityUnavailable("installed execution signer unavailable")
        payload = asdict(terminal)
        payload.pop("execution_signature")
        return hmac.new(self._component_signing_key,
                        canonical_json(payload).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def verify_installed_terminal(self, binding: InternalWorkBindingV1,
                                  claim: InternalWorkClaimV1,
                                  terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2) -> bool:
        """Bridge verifier: no caller-shaped V1 or unsigned actual is accepted."""
        if (type(terminal) is not InternalWorkTerminalV2 or
                terminal.status == "unknown" or
                not self.installed_runtime_verified or
                self._component_signing_key is None or
                binding.algorithm_ref != self.installed_algorithm_id or
                binding.algorithm_build_digest != self.installed_build_digest or
                claim != claim_internal_work_v1(binding) or
                terminal.binding_digest != binding.binding_digest or
                terminal.algorithm_id != binding.algorithm_ref or
                terminal.build_fingerprint != binding.algorithm_build_digest or
                terminal.input_digest != binding.input_digest):
            return False
        expected = self.sign_execution_terminal(terminal)
        if not hmac.compare_digest(expected, terminal.execution_signature):
            return False
        if (terminal.status == "completed" and
                self.installed_algorithm_id == "d06.association_activation.v3"):
            try:
                from .installed_c04_executor_v3 import decode_completed_c04_output_v3

                decode_completed_c04_output_v3(binding, terminal)
            except (AuthorityUnavailable, ImportError, TypeError, ValueError):
                return False
        return (terminal.status == "failed" or
                self._verified_component_completion(binding, terminal))

    def begin(self, binding: InternalWorkBindingV1) -> InternalWorkClaimV1:
        """Derive a stable intent only; no work may start before durable claim."""
        if (type(binding) is not InternalWorkBindingV1 or
                binding.namespace != self.journal.namespace):
            raise AuthorityUnavailable("internal work namespace differs")
        return claim_internal_work_v1(binding)

    def _port(self, name: str):
        method = getattr(type(self.journal), name, None)
        if not callable(method):
            raise AuthorityUnavailable(
                f"same-chain internal work journal port {name} is absent")
        return method

    def claim(self, binding: InternalWorkBindingV1, *,
              before_head: JournalHead) -> InternalWorkJournalAppendV1:
        claim = self.begin(binding)
        if (not callable(self._current_prepared_reader) or
                not callable(self._claim_port) or
                not callable(self._core_head_verifier)):
            raise AuthorityUnavailable("installed W01 preparation and Core-CAS claim port required")
        if (not self.installed_runtime_verified or
                binding.algorithm_ref != self.installed_algorithm_id or
                binding.algorithm_build_digest != self.installed_build_digest):
            raise AuthorityUnavailable("installed fixed C04 algorithm is unavailable")
        from ..runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1

        prepared = self._current_prepared_reader(binding)
        if (type(prepared) is not C04InternalWorkPreparedV1 or
                prepared.binding != binding):
            raise AuthorityUnavailable("current W01 internal work original differs")
        result = self._claim_port(binding, claim, before_head, prepared)
        self._check_append(result, binding, claim.mutation_id)
        self._require_current_core_head(result)
        return result

    def terminal(self, binding: InternalWorkBindingV1,
                 claim: InternalWorkClaimV1,
                 terminal: InternalWorkTerminalV1 | InternalWorkTerminalV2, *,
                 before_head: JournalHead) -> InternalWorkJournalAppendV1:
        if (claim != self.begin(binding) or
                type(terminal) not in (InternalWorkTerminalV1, InternalWorkTerminalV2) or
                terminal.binding_digest != binding.binding_digest or
                terminal.claim_mutation_id != claim.mutation_id):
            raise AuthorityUnavailable("internal work terminal differs from claim")
        if (not callable(self._terminal_port) or
                not callable(self._core_head_verifier)):
            raise AuthorityUnavailable("installed terminal measurement and Core-CAS port required")
        if not self.verify_installed_terminal(binding, claim, terminal):
            raise AuthorityUnavailable("untrusted C04 terminal measurement or component receipt")
        result = self._terminal_port(binding, claim, terminal, before_head)
        self._check_append(result, binding, terminal.mutation_id)
        self._require_current_core_head(result)
        return result

    def mark_unknown(self, binding: InternalWorkBindingV1,
                     claim: InternalWorkClaimV1, *,
                     before_head: JournalHead) -> InternalWorkJournalAppendV1:
        terminal = terminal_internal_work_v1(binding, claim, status="unknown")
        return self.terminal(binding, claim, terminal, before_head=before_head)

    def inspect(self, binding: InternalWorkBindingV1) -> InternalWorkJournalInspectionV1:
        self.begin(binding)
        result = self._port("read_internal_work_v1")(self.journal, binding)
        if (type(result) is not InternalWorkJournalInspectionV1 or
                result.binding != binding or
                type(result.verified_head) is not JournalHead or
                result.verified_head.journal_id != self.journal.journal_id):
            raise AuthorityUnavailable("independent internal work inspection differs")
        if result.claim is not None and self._original_reconciler is not None:
            self._original_reconciler(binding, "terminal" if result.terminal is not None else "claim")
        return result

    def verify_original_internal_work_terminal(
        self, proof: InternalWorkTerminalProofV1,
    ) -> AuthorityInternalWorkVerifiedReceiptV1:
        """D02 calls this outside the graph transaction; reread is mandatory."""
        if type(proof) is not InternalWorkTerminalProofV1:
            raise AuthorityUnavailable("typed internal work terminal proof required")
        validate_internal_work_terminal_proof_v1(
            proof, expected_binding=proof.binding)
        observed = self.inspect(proof.binding)
        if (not callable(self._core_head_verifier) or
                self._core_head_verifier(observed.verified_head) is not True):
            raise AuthorityUnavailable("current Core internal work head is unavailable")
        if (observed.claim != proof.claim or
                observed.terminal != proof.terminal or
                observed.claim_append is None or
                observed.terminal_append is None or
                proof.journal_head != JournalHead(
                    self.journal.journal_id,
                    observed.terminal_append.sequence,
                    observed.terminal_append.chain_digest) or
                (observed.claim_append.receipt_ref,
                 observed.claim_append.content_digest) !=
                (proof.claim_receipt_ref, proof.claim_receipt_digest) or
                (observed.terminal_append.receipt_ref,
                 observed.terminal_append.content_digest) !=
                (proof.terminal_receipt_ref, proof.terminal_receipt_digest)):
            raise AuthorityUnavailable("original internal work terminal is not current")
        binding, terminal = proof.binding, proof.terminal
        return AuthorityInternalWorkVerifiedReceiptV1(
            canonical_digest(proof), binding.namespace, binding.activity_id,
            binding.operation_id, binding.execution_id, binding.input_digest,
            binding.resource_quote_ref, binding.resource_quote_version,
            binding.resource_quote_digest, proof.terminal_receipt_ref,
            proof.terminal_receipt_digest, observed.terminal_append.sequence,
            observed.verified_head, terminal.status, terminal.actual_cpu_ms,
            self.verify_installed_terminal(binding, proof.claim, terminal) and
            self._verified_component_completion(binding, terminal),
        )

    def current_head_for_restore(self) -> JournalHead:
        """The Core restore adapter must reconcile this same journal head."""
        return self.journal.verified_head()

    def _check_append(self, append: object, binding: InternalWorkBindingV1,
                      mutation_id: str) -> None:
        if (type(append) is not InternalWorkJournalAppendV1 or
                (append.namespace, append.journal_id,
                 append.mutation_id, append.binding_digest) !=
                (binding.namespace, self.journal.journal_id,
                 mutation_id, binding.binding_digest)):
            raise AuthorityUnavailable("independent internal work append differs")
        if (type(append.sequence) is not int or append.sequence < 1 or
                type(append.content_digest) is not str or
                type(append.chain_digest) is not str or
                not append.receipt_ref):
            raise AuthorityUnavailable("independent internal work append malformed")
        identifier(append.receipt_ref, "internal_work_receipt_ref")

    def _require_current_core_head(self, append: InternalWorkJournalAppendV1) -> None:
        head = JournalHead(append.journal_id, append.sequence, append.chain_digest)
        if self._core_head_verifier(head) is not True:
            raise AuthorityUnavailable("internal work append lacks current Core CAS")


__all__ = [
    "AuthorityInternalWorkService", "InternalWorkJournalAppendV1",
    "InternalWorkJournalInspectionV1", "AuthorityInternalWorkVerifiedReceiptV1",
]
