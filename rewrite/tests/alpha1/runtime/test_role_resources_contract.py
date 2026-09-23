from dataclasses import asdict, replace

import pytest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.graph_types import GraphAtom
from sylanne3.runtime.role_resources import (
    ROLE_RESOURCES_TYPE, RoleRuntimeResourcesV1, read_role_resources,
    role_resources_write,
)
from sylanne3.runtime_contracts import NamespaceId


def selection() -> RoleRuntimeResourcesV1:
    return RoleRuntimeResourcesV1(
        "bot", "persona", "create-1", "plan-1", "plan-1@1", "blueprint:one",
        "sha256:" + "a" * 64, "capability:one", "provider/model", 3,
        "sha256:" + "b" * 64, "budget:one", "lease:one", 2,
        "sha256:" + "c" * 64,
    )


def test_d11_registers_exact_role_selection_and_read_checks_active_head():
    value = selection()
    write = role_resources_write(value)
    registry = discover_domain_registry().type_registry
    assert registry.spec(ROLE_RESOURCES_TYPE).writer_domain == "d11"
    assert registry.validate(write.key, write.value) == asdict(value)
    atom = GraphAtom(write.key, 1, write.value)
    assert read_role_resources(atom, namespace=value.namespace,
                               plan_id=value.plan_id, head_id=value.head_id) == value
    with pytest.raises(ValueError, match="unavailable"):
        read_role_resources(atom, namespace=NamespaceId("bot", "other"),
                            plan_id=value.plan_id, head_id=value.head_id)
    with pytest.raises(ValueError, match="active head"):
        read_role_resources(atom, namespace=value.namespace,
                            plan_id=value.plan_id, head_id="plan-1@2")


def test_selection_rejects_activation_claim_and_credential_field():
    value = selection()
    with pytest.raises(ValueError, match="cannot claim activation"):
        replace(value, state="active")
    registry = discover_domain_registry().type_registry
    write = role_resources_write(value)
    with pytest.raises(ValueError, match="exact v1 fields"):
        registry.validate(write.key, {**write.value, "credential_ref": "secret"})
