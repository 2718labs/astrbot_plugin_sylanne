"""D03 can describe a binding check without granting D11 final send authority."""

from dataclasses import replace

import pytest

from sylanne3.domains.d03 import ContextProvider, RoleBindingRequest, RoleBindingResolution
from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, QueryEpoch, VersionedRef, canonical_digest,
)


NAMESPACE = NamespaceId("bot", "persona")
KEY = AtomKey(
    Owner("scene", "bot", "persona", "scene:project"),
    "d03.role_binding", "binding:project",
)
CRITERIA = VersionedRef("criteria:d03", 1)
EPOCH = VersionedRef("d03.role_binding", 4)
BINDING = VersionedRef("binding:project", 2)


def _intent(*, versions=(CRITERIA, EPOCH, BINDING), target="entity:alice"):
    spec = RequiredCheckSpec(
        "role_binding", "d03.role_binding", "persona:persona", "action:message",
        "respond", CRITERIA.ref, versions,
    )
    return ActionIntent(
        "action:message", 1, "goal:reply", (), target, "message", "respond",
        "reversible", canonical_digest({"text": "hello"}),
        OperationIdentity(
            "activity:reply", "effect:reply", "attempt:1", "prepare",
            "operation:reply", canonical_digest({"inputs": []}),
        ),
        "schema:reply", (spec,),
        GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
        ("message:reply",), None, ("source:request",),
    )


def _resolution(*, status="complete", complete=True, target="entity:alice"):
    return RoleBindingResolution(
        status, ("binding:project",) if status == "complete" else (),
        ("norm:project",) if status == "complete" else (),
        ("scope_coverage",) if not complete else (),
        (GraphVersion(KEY, 2),), QueryEpoch(NAMESPACE, "d03.role_binding", 4),
        12.0,
        RoleBindingRequest(
            "persona:persona", target, None, "scene:project", "message", "respond",
            5.0, complete,
        ),
    )


def test_role_binding_receipt_requires_pinned_current_graph_and_scope():
    receipt = ContextProvider().provide_required_check(
        _intent(), _resolution(), valid_until=10.0,
    )
    assert receipt.coverage == "full"
    assert receipt.result == "pass"
    assert receipt.input_versions == (CRITERIA, EPOCH, BINDING)
    assert receipt.issuer == "d03.role_binding"


@pytest.mark.parametrize("resolution", [
    _resolution(status="partial", complete=False),
    _resolution(status="stale"),
    _resolution(status="no_applicable_binding"),
    _resolution(target="entity:other"),
])
def test_incomplete_stale_missing_or_wrong_target_never_passes(resolution):
    receipt = ContextProvider().provide_required_check(
        _intent(), resolution, valid_until=10.0,
    )
    assert receipt.result == "unknown"


def test_mismatched_graph_inputs_or_expired_binding_never_pass():
    provider = ContextProvider()
    wrong_epoch = _intent(versions=(CRITERIA, VersionedRef("d03.role_binding", 3), BINDING))
    assert provider.provide_required_check(
        wrong_epoch, _resolution(), valid_until=10.0,
    ).result == "unknown"
    assert provider.provide_required_check(
        _intent(), replace(_resolution(), valid_until=9.0), valid_until=10.0,
    ).result == "unknown"


def test_missing_d03_spec_is_rejected():
    intent = _intent()
    other = replace(intent.required_checks[0], provider_id="another.provider")
    with pytest.raises(ValueError, match="exactly one"):
        ContextProvider().provide_required_check(
            replace(intent, required_checks=(other,)), _resolution(), valid_until=10.0,
        )
