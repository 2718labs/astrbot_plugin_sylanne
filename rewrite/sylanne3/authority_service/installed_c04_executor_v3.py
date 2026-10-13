"""Installed, single-thread C04 V3 executor for one frozen D06 algorithm.

The W01 reader must return the original persisted input.  No caller-provided
callable, result, or CPU measurement enters this port.  A claim-only replay is
always observational, including after process restart.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import time
from typing import Callable

from ..contracts import canonical_json
from .. import memory_association as activation_kernel
from ..domains.d06 import c04_work_algorithm_v3 as algorithm
from ..domains.d06 import c04_work_algorithm_v4 as algorithm_v4
from ..runtime.c04_direct_seed_v4 import AssociationWorkInputV4, AssociationWorkResultV4
from ..runtime.c04_v3_contracts import AssociationWorkInputV3, AssociationWorkResultV3
from ..runtime_contracts import NamespaceId
from .contract import AuthorityUnavailable, JournalHead
from .internal_work_contract import InternalWorkBindingV1, InternalWorkTerminalV2
from .internal_work_contract import _phase_id
from .internal_work_service import (
    AuthorityInternalWorkService, InternalWorkJournalInspectionV1,
)
from .v2_execution_bridge import AuthorityV2ExecutionBridge


ALGORITHM_ID = algorithm.ALGORITHM_ID
ALGORITHM_ID_V4 = algorithm_v4.ALGORITHM_ID


_OUTPUT_SCHEMA = "sylanne.d06.association-work-terminal-output.v3"
_OUTPUT_FIELDS = {"schema", "algorithm_id", "algorithm_build_digest",
                  "input_digest", "result_digest", "result_json"}


def decode_completed_c04_output_v3(
    binding: InternalWorkBindingV1, terminal: InternalWorkTerminalV2,
) -> AssociationWorkResultV3:
    return _decode_completed_c04_output(binding, terminal, algorithm_id=ALGORITHM_ID,
        schema=_OUTPUT_SCHEMA, result_type=AssociationWorkResultV3)


def decode_completed_c04_output_v4(
    binding: InternalWorkBindingV1, terminal: InternalWorkTerminalV2,
) -> AssociationWorkResultV4:
    return _decode_completed_c04_output(binding, terminal, algorithm_id=ALGORITHM_ID_V4,
        schema="sylanne.d06.association-work-terminal-output.direct_seed.v4",
        result_type=AssociationWorkResultV4)


def _decode_completed_c04_output(binding, terminal, *, algorithm_id, schema, result_type):
    """Strictly decode signed completed bytes before adopting any V3 result."""
    if (type(binding) is not InternalWorkBindingV1 or
            type(terminal) is not InternalWorkTerminalV2 or
            terminal.status != "completed" or
            binding.algorithm_ref != algorithm_id or
            terminal.algorithm_id != algorithm_id or
            terminal.binding_digest != binding.binding_digest or
            terminal.input_digest != binding.input_digest or
            terminal.build_fingerprint != binding.algorithm_build_digest or
            type(terminal.output_json) is not str):
        raise AuthorityUnavailable("C04 V3 terminal identity differs")
    try:
        envelope = json.loads(terminal.output_json)
        if (type(envelope) is not dict or set(envelope) != _OUTPUT_FIELDS or
                canonical_json(envelope) != terminal.output_json or
                envelope["schema"] != schema or
                envelope["algorithm_id"] != algorithm_id or
                envelope["algorithm_build_digest"] !=
                "sha256:" + binding.algorithm_build_digest or
                envelope["input_digest"] != "sha256:" + binding.input_digest or
                envelope["result_digest"] != "sha256:" + terminal.result_digest):
            raise ValueError("terminal envelope differs")
        result = result_type.from_json(envelope["result_json"])
        from ..graph_coordinator import namespace_ref

        if ((result.algorithm_id, result.algorithm_build_digest,
             result.input_digest, result.result_digest,
             result.operation_id) !=
            (algorithm_id, envelope["algorithm_build_digest"],
             envelope["input_digest"], envelope["result_digest"],
             binding.operation_id) or
                namespace_ref(result.namespace) != binding.namespace):
            raise ValueError("terminal result differs")
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityUnavailable("C04 V3 terminal output is malformed") from exc
    return result


class InstalledC04ExecutorV3:
    """Authority-process orchestration; service ports own claim and Core CAS."""

    def __init__(self, service: AuthorityInternalWorkService, *,
                 frozen_input_reader: Callable[[InternalWorkBindingV1],
                                               AssociationWorkInputV3]):
        if type(service) is not AuthorityInternalWorkService:
            raise TypeError("installed internal work service required")
        if not callable(frozen_input_reader):
            raise AuthorityUnavailable("W01 frozen original reader is unavailable")
        if not service.installed_runtime_verified:
            raise AuthorityUnavailable("production-qualified installed D06 manifest pin is unavailable")
        self._service = service
        self._frozen_input_reader = frozen_input_reader

    def inspect(self, binding: InternalWorkBindingV1) -> InternalWorkJournalInspectionV1:
        return self._service.inspect(binding)

    def execute(self, binding: InternalWorkBindingV1) -> InternalWorkJournalInspectionV1:
        """Start once; every existing claim is query-only and never re-run."""
        if (type(binding) is not InternalWorkBindingV1 or
                binding.algorithm_ref not in {ALGORITHM_ID, ALGORITHM_ID_V4} or
                not self._service.accepts_installed_binding(binding)):
            raise AuthorityUnavailable("installed C04 algorithm/build identity differs")
        observed = self._service.inspect(binding)
        if observed.claim is not None:
            return observed
        work = self._frozen_input_reader(binding)
        input_type, activate, decoder, output_schema = (
            (AssociationWorkInputV4, algorithm_v4.activate_association_work_v4,
             decode_completed_c04_output_v4,
             "sylanne.d06.association-work-terminal-output.direct_seed.v4")
            if binding.algorithm_ref == ALGORITHM_ID_V4 else
            (AssociationWorkInputV3, algorithm.activate_association_work_v3,
             decode_completed_c04_output_v3, _OUTPUT_SCHEMA))
        if (type(work) is not input_type or
                work.algorithm_id != binding.algorithm_ref or
                work.algorithm_build_digest !=
                "sha256:" + binding.algorithm_build_digest or
                work.input_digest != "sha256:" + binding.input_digest or
                work.activity_id != binding.activity_id or
                work.operation_id != binding.operation_id):
            raise AuthorityUnavailable("frozen W01 association input differs")
        from ..graph_coordinator import namespace_ref

        if namespace_ref(work.namespace) != binding.namespace:
            raise AuthorityUnavailable("frozen W01 association namespace differs")
        # A racing caller may consume the claim after the initial inspection.
        # The claim port denies that replay; this invocation cannot execute.
        claim_append = self._service.claim(
            binding, before_head=observed.verified_head)
        claim = self._service.begin(binding)
        start = time.thread_time_ns()
        try:
            result = activate(work)
        except Exception:
            elapsed = time.thread_time_ns() - start
            result = None
        else:
            elapsed = time.thread_time_ns() - start
        output = None
        if result is not None:
            try:
                output = canonical_json({
                    "schema": output_schema,
                    "algorithm_id": binding.algorithm_ref,
                    "algorithm_build_digest": "sha256:" + binding.algorithm_build_digest,
                    "input_digest": work.input_digest,
                    "result_digest": result.result_digest,
                    "result_json": result.to_json(),
                })
                if len(output.encode("utf-8")) > 65536:
                    raise ValueError("C04 installed result exceeds terminal bound")
            except Exception:
                output = None
        if output is None:
            terminal = InternalWorkTerminalV2(
                binding.binding_digest, claim.mutation_id,
                _phase_id(binding.binding_digest, "terminal"),
                "failed", (elapsed + 999_999) // 1_000_000,
                binding.algorithm_ref, binding.algorithm_build_digest, binding.input_digest,
                None, None, None, None, None, "0" * 64)
        else:
            terminal = InternalWorkTerminalV2(
                binding.binding_digest, claim.mutation_id,
                _phase_id(binding.binding_digest, "terminal"),
                "completed", (elapsed + 999_999) // 1_000_000,
                binding.algorithm_ref, binding.algorithm_build_digest, binding.input_digest,
                result.result_digest.removeprefix("sha256:"), output,
                "internal-work:component:" + binding.binding_digest,
                "0" * 64, "0" * 64, "0" * 64)
            receipt_digest, signature = self._service.sign_component_completion(
                binding, terminal)
            terminal = replace(terminal, component_receipt_digest=receipt_digest,
                               component_receipt_signature=signature)
        terminal = replace(
            terminal, execution_signature=self._service.sign_execution_terminal(terminal))
        if terminal.status == "completed":
            decoder(binding, terminal).validate_input(work)
        self._service.terminal(
            binding, claim, terminal,
            before_head=JournalHead(claim_append.journal_id,
                                    claim_append.sequence, claim_append.chain_digest))
        return self._service.inspect(binding)


def compose_installed_c04_service_v3(
    *, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId,
    graph_db_path: str | Path,
    package_root: str | Path,
    trusted_manifest_sha256: str,
    component_signing_key: bytes,
    credential: object,
    resource_issuer,
    budget_issuer,
    self_identity_read_credential: object | None = None,
    install_bridge_verifier: bool = True,
) -> AuthorityInternalWorkService:
    """Install C04 from pinned formal package and immutable W01 originals.

    The manifest hash must come from administrator installation state outside
    the package.  This factory invokes the verifier in the Authority process;
    a Host-provided proof dictionary is never sufficient.
    """
    from ..graph_coordinator import namespace_ref

    if (type(bridge) is not AuthorityV2ExecutionBridge or
            type(namespace) is not NamespaceId or
            bridge.namespace != namespace_ref(namespace) or
            type(trusted_manifest_sha256) is not str or
            len(trusted_manifest_sha256) != 64 or
            any(char not in "0123456789abcdef"
                for char in trusted_manifest_sha256)):
        raise AuthorityUnavailable("C04 installed namespace or external manifest pin differs")
    if type(component_signing_key) is not bytes or len(component_signing_key) != 32:
        raise AuthorityUnavailable("C04 protected persistent signing key is unavailable")
    graph_path = Path(graph_db_path).resolve(strict=True)
    if not graph_path.is_file():
        raise AuthorityUnavailable("pinned C04 graph database is unavailable")
    from ..host.installed_d06_build import (
        ENTRY_PATH_V3, ENTRY_PATH_V4, KERNEL_PATH, verify_d06_algorithm_build,
    )
    try:
        build = verify_d06_algorithm_build(
            Path(package_root), trusted_manifest_sha256,
            require_formal=False, require_backend_runtime=True, algorithm_id=ALGORITHM_ID)
        build_v4 = verify_d06_algorithm_build(
            Path(package_root), trusted_manifest_sha256,
            require_formal=False, require_backend_runtime=True, algorithm_id=ALGORITHM_ID_V4)
    except (OSError, TypeError, ValueError) as exc:
        raise AuthorityUnavailable("production-qualified D06 package bytes are unverified") from exc
    digest = build.get("build_digest") if type(build) is dict else None
    if (type(digest) is not str or not digest.startswith("sha256:") or
            len(digest) != 71):
        raise AuthorityUnavailable("formal D06 build digest is absent")
    package_path = Path(package_root).resolve(strict=True)
    if (Path(algorithm.__file__).resolve(strict=True) !=
            (package_path / ENTRY_PATH_V3).resolve(strict=True) or
            Path(algorithm_v4.__file__).resolve(strict=True) !=
            (package_path / ENTRY_PATH_V4).resolve(strict=True) or
            Path(activation_kernel.__file__).resolve(strict=True) !=
            (package_path / KERNEL_PATH).resolve(strict=True)):
        raise AuthorityUnavailable("loaded D06 code differs from verified installation")

    def read_graph_original(binding: InternalWorkBindingV1, *, frozen: bool):
        if type(binding) is not InternalWorkBindingV1:
            raise AuthorityUnavailable("typed C04 original binding required")
        if Path(graph_db_path).resolve(strict=True) != graph_path:
            raise AuthorityUnavailable("pinned C04 graph database path changed")
        db = sqlite3.connect(f"file:{graph_path.as_posix()}?mode=ro", uri=True)
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            if frozen:
                from ..runtime.c04_frozen_association_original_v3 import (
                    read_c04_frozen_association_original_v3,
                    read_c04_frozen_association_original_v4,
                )
                reader = (read_c04_frozen_association_original_v4
                          if binding.algorithm_ref == ALGORITHM_ID_V4 else
                          read_c04_frozen_association_original_v3)
                original = reader(db, namespace, binding)
            else:
                from ..runtime.c04_internal_work_original_v1 import (
                    read_c04_internal_work_prepared_v1,
                )
                original = read_c04_internal_work_prepared_v1(
                    db, namespace, binding.operation_id)
            db.commit()
        finally:
            db.close()
        if original is None:
            raise AuthorityUnavailable("durable W01 C04 original is absent")
        return original

    from .c04_current_execution_v3 import InstalledC04CurrentReaderV3
    from .c04_exclusive_execution_v3 import (
        claim_exclusive_c04_v3, terminal_exclusive_c04_v3,
        reconcile_exclusive_c04_v3)
    current_reader = InstalledC04CurrentReaderV3(namespace=namespace, graph_path=graph_path,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        foreground_observer=bridge._current_foreground_reply_scope_observer_v1)

    def claim_port(binding, claim, before_head, prepared):
        return claim_exclusive_c04_v3(bridge,
            credential=credential, binding=binding, claim=claim,
            before_head=before_head, prepared=prepared, current_reader=current_reader,
            self_identity_read_credential=self_identity_read_credential)

    def terminal_port(binding, claim, terminal, before_head):
        return terminal_exclusive_c04_v3(bridge,
            credential=credential, binding=binding, claim=claim,
            terminal=terminal)

    service = AuthorityInternalWorkService(
        bridge.journal,
        current_prepared_reader=lambda binding: read_graph_original(
            binding, frozen=False),
        claim_port=claim_port, terminal_port=terminal_port,
        core_head_verifier=lambda head: bridge.is_current_internal_work_head_v1(
            credential=credential, head=head),
        component_signing_key=component_signing_key,
        installed_build_digest=digest.removeprefix("sha256:"),
        installed_build_attestation=build,
        installed_build_attestations=(build_v4,),
        trusted_manifest_sha256=trusted_manifest_sha256,
        original_reconciler=lambda binding, phase: reconcile_exclusive_c04_v3(
            bridge, credential=credential, binding=binding, phase=phase),
    )
    service._installed_current_reader_v3 = current_reader
    if type(install_bridge_verifier) is not bool:
        raise AuthorityUnavailable("C04 bridge verifier install mode differs")
    if install_bridge_verifier:
        bridge.install_internal_work_terminal_verifier(service.verify_installed_terminal)
    service._installed_frozen_input_reader = lambda binding: read_graph_original(binding, frozen=True)
    return service


def compose_installed_c04_executor_v3(
    *, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId,
    graph_db_path: str | Path,
    package_root: str | Path,
    trusted_manifest_sha256: str,
    component_signing_key: bytes,
    credential: object,
    resource_issuer,
    budget_issuer,
    self_identity_read_credential: object | None = None,
    install_bridge_verifier: bool = True,
) -> tuple[AuthorityInternalWorkService, InstalledC04ExecutorV3]:
    """Add the executor to the same formally installed historical service."""
    service = compose_installed_c04_service_v3(
        bridge=bridge,
        namespace=namespace,
        graph_db_path=graph_db_path,
        package_root=package_root,
        trusted_manifest_sha256=trusted_manifest_sha256,
        component_signing_key=component_signing_key,
        credential=credential,
        resource_issuer=resource_issuer,
        budget_issuer=budget_issuer,
        self_identity_read_credential=self_identity_read_credential,
        install_bridge_verifier=install_bridge_verifier)
    executor = InstalledC04ExecutorV3(service,
        frozen_input_reader=service._installed_frozen_input_reader)
    executor._current_reader = service._installed_current_reader_v3
    return service, executor


__all__ = ["ALGORITHM_ID", "InstalledC04ExecutorV3",
           "compose_installed_c04_executor_v3", "compose_installed_c04_service_v3", "decode_completed_c04_output_v3",
           "decode_completed_c04_output_v4", "ALGORITHM_ID_V4"]
