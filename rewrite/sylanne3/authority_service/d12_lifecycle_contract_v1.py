"""Typed whole-Host maintenance controls, separate from role pause semantics."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import re

from ..runtime.lifecycle_operations_v1 import digest

STAGES = frozenset({"quiescing", "drained", "stop_intent", "paused", "resuming", "start_intent", "ready", "active"})


@dataclass(frozen=True, slots=True)
class D12InstallationControlIntentV1:
    installation_id: str
    action: str
    expected_lifecycle_epoch: int
    prior_pause_operation_id: str | None
    scope: str = "whole_host"
    schema: str = "d12.installation_control.v1"

    @classmethod
    def from_command(cls, command):
        expected = {"schema", "scope", "expected_lifecycle_epoch", "prior_pause_operation_id"}
        values = command.config_diff
        if (command.control not in {"pause", "resume"} or command.test_intent is not None
                or not command.object_ref.startswith("installation:")
                or set(values) != expected or values["schema"] != "d12.installation_control.v1"
                or values["scope"] != "whole_host"):
            raise ValueError("explicit versioned whole-Host pause/resume intent required")
        return cls(command.object_ref.removeprefix("installation:"), command.control,
            values["expected_lifecycle_epoch"], values["prior_pause_operation_id"])

    def __post_init__(self):
        if (not self.installation_id or self.action not in {"pause", "resume"}
                or self.scope != "whole_host" or self.schema != "d12.installation_control.v1"
                or type(self.expected_lifecycle_epoch) is not int or self.expected_lifecycle_epoch < 0
                or (self.action == "pause") != (self.prior_pause_operation_id is None)):
            raise ValueError("whole-Host lifecycle intent identity differs")
        if self.prior_pause_operation_id is not None and (type(self.prior_pause_operation_id) is not str or not self.prior_pause_operation_id):
            raise ValueError("resume must name its exact paused operation")


@dataclass(frozen=True, slots=True)
class D12InstallationLifecycleReceiptV1:
    authority_namespace: str
    installation_id: str
    operation_id: str
    request_digest: str
    action: str
    stage: str
    lifecycle_epoch: int
    business_generation: int
    owner_head: str
    storage_identity_digest: str
    namespace_anchor_digest: str
    constraint_projection_digest: str | None
    supervisor_observation_digest: str | None
    process_identity_digest: str | None
    bootstrap_original_ref: str | None
    live_fence_count: int
    pending_mutation_count: int
    active_rpc_count: int
    prior_receipt_digest: str | None
    original_ref: str
    original_digest: str
    scope: str = "whole_host"
    schema: str = "d12.installation_lifecycle_receipt.v1"

    def __post_init__(self):
        if self.schema != "d12.installation_lifecycle_receipt.v1" or self.scope != "whole_host" or self.stage not in STAGES or self.action not in {"pause", "resume"}:
            raise ValueError("lifecycle receipt kind differs")
        for name in ("lifecycle_epoch", "business_generation", "live_fence_count", "pending_mutation_count", "active_rpc_count"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 0:
                raise ValueError("lifecycle receipt requires actual nonnegative counts/versions")
        for name in ("request_digest", "storage_identity_digest", "namespace_anchor_digest", "original_digest"):
            if re.fullmatch(r"sha256:[0-9a-f]{64}", getattr(self, name)) is None:
                raise ValueError("lifecycle receipt digest differs")
        if self.stage in {"drained", "paused", "ready", "active"} and (
                self.live_fence_count or self.pending_mutation_count or self.active_rpc_count):
            raise ValueError("lifecycle settled stage lacks actual drain")
        material = {field.name: getattr(self, field.name) for field in fields(self) if field.name != "original_digest"}
        if digest(material) != self.original_digest:
            raise ValueError("lifecycle original commitment differs")


def lifecycle_receipt_from_wire_v1(value):
    if type(value) is not dict or set(value) != set(D12InstallationLifecycleReceiptV1.__dataclass_fields__):
        raise ValueError("lifecycle receipt fields differ")
    return D12InstallationLifecycleReceiptV1(**value)


__all__ = ("D12InstallationControlIntentV1", "D12InstallationLifecycleReceiptV1", "lifecycle_receipt_from_wire_v1", "STAGES")
