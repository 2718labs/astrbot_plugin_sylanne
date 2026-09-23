"""D11 role resource selection stored beside the initial D01 head.

This records verified selection provenance. It does not grant a model call or
reserve a budget; those require current host and D11 admissions at use time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import re

from ..graph_types import AtomKey, GraphAtom, GraphWrite, Owner, TypeSpec
from ..runtime_contracts import NamespaceId, schema_hash


ROLE_RESOURCES_TYPE = "runtime.role_resources.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _text(value: object, name: str) -> None:
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError(f"{name} must be a bounded nonempty string")


@dataclass(frozen=True, slots=True)
class RoleRuntimeResourcesV1:
    bot_id: str
    persona_id: str
    operation_id: str
    plan_id: str
    head_id: str
    blueprint_ref: str
    blueprint_digest: str
    model_capability_ref: str
    model_resource_ref: str
    model_revision: int
    model_digest: str
    budget_ref: str
    budget_lease_ref: str
    budget_version: int
    budget_digest: str
    state: str = "selected_only"

    def __post_init__(self) -> None:
        for name in ("bot_id", "persona_id", "operation_id", "plan_id", "head_id",
                     "blueprint_ref", "model_capability_ref", "model_resource_ref",
                     "budget_ref", "budget_lease_ref"):
            _text(getattr(self, name), name)
        if (not self.head_id.startswith(self.plan_id + "@")
                or not self.head_id[len(self.plan_id) + 1:].isdecimal()
                or int(self.head_id[len(self.plan_id) + 1:]) < 1):
            raise ValueError("head_id does not identify plan_id")
        for name in ("blueprint_digest", "model_digest", "budget_digest"):
            digest = getattr(self, name)
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise ValueError(f"{name} must be a SHA-256 digest")
        for name in ("model_revision", "budget_version"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive revision")
        if self.state != "selected_only":
            raise ValueError("role resource selection cannot claim activation")

    @property
    def namespace(self) -> NamespaceId:
        return NamespaceId(self.bot_id, self.persona_id)


def _decode(value: object) -> RoleRuntimeResourcesV1:
    if type(value) is not dict or set(value) != {field.name for field in fields(RoleRuntimeResourcesV1)}:
        raise ValueError("role resources require exact v1 fields")
    return RoleRuntimeResourcesV1(**value)


def role_resources_spec() -> TypeSpec:
    return TypeSpec(
        ROLE_RESOURCES_TYPE, ("persona",), "state", _decode,
        writer_domain="d11",
        schema_hash=schema_hash({
            "type": ROLE_RESOURCES_TYPE, "schema_version": 1,
            "owner_kinds": ["persona"], "storage_role": "state",
            "writer_domain": "d11",
            "fields": [field.name for field in fields(RoleRuntimeResourcesV1)],
        }),
    )


def role_resources_key(namespace: NamespaceId, plan_id: str) -> AtomKey:
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace must be NamespaceId")
    _text(plan_id, "plan_id")
    return AtomKey(Owner("persona", *namespace.as_tuple), ROLE_RESOURCES_TYPE, plan_id)


def role_resources_write(value: RoleRuntimeResourcesV1) -> GraphWrite:
    if type(value) is not RoleRuntimeResourcesV1:
        raise TypeError("role resources must be typed")
    return GraphWrite(role_resources_key(value.namespace, value.plan_id), asdict(value))


def read_role_resources(atom: GraphAtom, *, namespace: NamespaceId,
                        plan_id: str, head_id: str) -> RoleRuntimeResourcesV1:
    if (type(atom) is not GraphAtom or not atom.valid
            or atom.key != role_resources_key(namespace, plan_id)
            or type(atom.revision) is not int or atom.revision < 1):
        raise ValueError("current role resource atom is unavailable")
    value = _decode(atom.value)
    if value.namespace != namespace or value.plan_id != plan_id or value.head_id != head_id:
        raise ValueError("role resource selection differs from active head")
    return value


__all__ = (
    "ROLE_RESOURCES_TYPE", "RoleRuntimeResourcesV1", "role_resources_spec",
    "role_resources_key", "role_resources_write", "read_role_resources",
)
