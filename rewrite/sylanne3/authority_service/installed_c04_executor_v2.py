"""Installed, single-thread C04 executor for one frozen D06 algorithm.

The W01 reader must return the original persisted input.  No caller-provided
callable, result, or CPU measurement enters this port.  A claim-only replay is
always observational, including after process restart.
"""

from __future__ import annotations

from dataclasses import asdict, replace
import json
from pathlib import Path
import sqlite3
import time
from typing import Callable

from ..contracts import canonical_json
from .. import memory_association as activation_kernel
from ..domains.d06 import c04_work_input_v2 as algorithm
from ..domains.d06.c04_work_input_v2 import AssociationWorkInputV2
from ..runtime_contracts import canonical_serialize
from ..runtime_contracts import NamespaceId
from .contract import AuthorityUnavailable, JournalHead
from .internal_work_contract import InternalWorkBindingV1, InternalWorkTerminalV2
from .internal_work_contract import _phase_id
from .internal_work_service import (
    AuthorityInternalWorkService, InternalWorkJournalInspectionV1,
)
from .v2_execution_bridge import AuthorityV2ExecutionBridge


ALGORITHM_ID = algorithm.ALGORITHM_ID


class InstalledC04ExecutorV2:
    """Authority-process orchestration; service ports own claim and Core CAS."""

    def __init__(self, service: AuthorityInternalWorkService, *,
                 frozen_input_reader: Callable[[InternalWorkBindingV1],
                                               AssociationWorkInputV2]):
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
                binding.algorithm_ref != ALGORITHM_ID or
                binding.algorithm_build_digest !=
                self._service.installed_build_digest):
            raise AuthorityUnavailable("installed C04 algorithm/build identity differs")
        observed = self._service.inspect(binding)
        if observed.claim is not None:
            return observed
        work = self._frozen_input_reader(binding)
        if (type(work) is not AssociationWorkInputV2 or
                work.algorithm_id != ALGORITHM_ID or
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
            result = algorithm.activate_association_work_v2(work)
        except Exception:
            elapsed = time.thread_time_ns() - start
            result = None
        else:
            elapsed = time.thread_time_ns() - start
        output = None
        if result is not None:
            try:
                output = canonical_json(json.loads(canonical_serialize(asdict(result))))
                if len(output.encode("utf-8")) > 65536:
                    raise ValueError("C04 installed result exceeds terminal bound")
            except Exception:
                output = None
        if output is None:
            terminal = InternalWorkTerminalV2(
                binding.binding_digest, claim.mutation_id,
                _phase_id(binding.binding_digest, "terminal"),
                "failed", (elapsed + 999_999) // 1_000_000,
                ALGORITHM_ID, binding.algorithm_build_digest, binding.input_digest,
                None, None, None, None, None, "0" * 64)
        else:
            terminal = InternalWorkTerminalV2(
                binding.binding_digest, claim.mutation_id,
                _phase_id(binding.binding_digest, "terminal"),
                "completed", (elapsed + 999_999) // 1_000_000,
                ALGORITHM_ID, binding.algorithm_build_digest, binding.input_digest,
                result.result_digest.removeprefix("sha256:"), output,
                "internal-work:component:" + binding.binding_digest,
                "0" * 64, "0" * 64, "0" * 64)
            receipt_digest, signature = self._service.sign_component_completion(
                binding, terminal)
            terminal = replace(terminal, component_receipt_digest=receipt_digest,
                               component_receipt_signature=signature)
        terminal = replace(
            terminal, execution_signature=self._service.sign_execution_terminal(terminal))
        self._service.terminal(
            binding, claim, terminal,
            before_head=JournalHead(claim_append.journal_id,
                                    claim_append.sequence, claim_append.chain_digest))
        return self._service.inspect(binding)


def compose_installed_c04_service_v2(
    *, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId,
    graph_db_path: str | Path,
    package_root: str | Path,
    trusted_manifest_sha256: str,
    component_signing_key: bytes,
    credential: object,
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
        ENTRY_PATH, KERNEL_PATH, verify_d06_algorithm_build,
    )
    try:
        build = verify_d06_algorithm_build(
            Path(package_root), trusted_manifest_sha256, require_formal=False, require_backend_runtime=True)
    except (OSError, TypeError, ValueError) as exc:
        raise AuthorityUnavailable("production-qualified D06 package bytes are unverified") from exc
    digest = build.get("build_digest") if type(build) is dict else None
    if (type(digest) is not str or not digest.startswith("sha256:") or
            len(digest) != 71):
        raise AuthorityUnavailable("formal D06 build digest is absent")
    package_path = Path(package_root).resolve(strict=True)
    if (Path(algorithm.__file__).resolve(strict=True) !=
            (package_path / ENTRY_PATH).resolve(strict=True) or
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
                from ..runtime.c04_frozen_association_original_v2 import (
                    read_c04_frozen_association_original_v2,
                )
                original = read_c04_frozen_association_original_v2(
                    db, namespace, binding)
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

    def claim_port(binding, claim, before_head, prepared):
        return bridge.append_internal_work_claim_v1(
            credential=credential, binding=binding, claim=claim,
            before_head=before_head, prepared=prepared)

    def terminal_port(binding, claim, terminal, before_head):
        return bridge.append_internal_work_terminal_v1(
            credential=credential, binding=binding, claim=claim,
            terminal=terminal, before_head=before_head)

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
        trusted_manifest_sha256=trusted_manifest_sha256,
    )
    if type(install_bridge_verifier) is not bool:
        raise AuthorityUnavailable("C04 bridge verifier install mode differs")
    if install_bridge_verifier:
        bridge.install_internal_work_terminal_verifier(service.verify_installed_terminal)
    service._installed_frozen_input_reader = lambda binding: read_graph_original(binding, frozen=True)
    return service


def compose_installed_c04_executor_v2(
    *, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId,
    graph_db_path: str | Path,
    package_root: str | Path,
    trusted_manifest_sha256: str,
    component_signing_key: bytes,
    credential: object,
    install_bridge_verifier: bool = True,
) -> tuple[AuthorityInternalWorkService, InstalledC04ExecutorV2]:
    """Add the executor to the same formally installed historical service."""
    service = compose_installed_c04_service_v2(
        bridge=bridge,
        namespace=namespace,
        graph_db_path=graph_db_path,
        package_root=package_root,
        trusted_manifest_sha256=trusted_manifest_sha256,
        component_signing_key=component_signing_key,
        credential=credential,
        install_bridge_verifier=install_bridge_verifier)
    executor = InstalledC04ExecutorV2(service,
        frozen_input_reader=service._installed_frozen_input_reader)
    return service, executor


__all__ = ["ALGORITHM_ID", "InstalledC04ExecutorV2",
           "compose_installed_c04_executor_v2", "compose_installed_c04_service_v2"]
