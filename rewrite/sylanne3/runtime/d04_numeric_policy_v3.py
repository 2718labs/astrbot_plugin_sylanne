"""Administrator limits for the measured installed full/LOO numeric recipe."""
from __future__ import annotations
from dataclasses import dataclass
import math
from ..runtime_contracts import NamespaceId
from ..authority_service.d04_numeric_contract_v3 import WORK_KIND


@dataclass(frozen=True, slots=True)
class AdminD04JointNumericPolicyV3:
    namespace: NamespaceId
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    cpu_ceiling_ms: int
    max_iterations: int
    tolerance: float
    job_lifetime_seconds: int
    version: int = 3

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or self.version != 3
                or any(type(v) is not str or not v for v in (self.installation_id, self.grant_id, self.lease_id))
                or type(self.grant_version) is not int or self.grant_version < 1
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 3_600_000
                or type(self.max_iterations) is not int or not 1 <= self.max_iterations <= 256
                or type(self.tolerance) is not float or not math.isfinite(self.tolerance) or not 0 < self.tolerance <= 1
                or type(self.job_lifetime_seconds) is not int or not 1 <= self.job_lifetime_seconds <= 3600):
            raise ValueError("D04 installed numeric policy requires explicit bounded limits")


def numeric_policy_from_payload_v3(payload, installation):
    raw = payload.get("d04_joint_numeric")
    if raw is None:
        return None
    if type(raw) is not dict or set(raw) != {"version", "cpu_ceiling_ms", "max_iterations", "tolerance", "job_lifetime_seconds"}:
        raise ValueError("D04 joint numeric policy fields differ")
    grant, lease = installation.root_grant, installation.root_lease
    policy = AdminD04JointNumericPolicyV3(installation.namespace, installation.installation_id,
        grant.grant_id, grant.version, lease.lease_id, **raw)
    if (WORK_KIND not in grant.allowed_work_kinds
            or policy.cpu_ceiling_ms > grant.max_ceiling.get("cpu_ms", 0)
            or policy.cpu_ceiling_ms > lease.limits.get("cpu_ms", 0)):
        raise ValueError("D04 numeric policy exceeds the actual signed root CPU authority")
    return policy
