"""An explicit installed policy only adds expression to a private source."""

from dataclasses import replace

import pytest

from sylanne3.host.authority_profile import AdminD06PrivateReplySourcePolicy
from sylanne3.host.d06_ingress import source_admission_from_host
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.runtime_contracts import NamespaceId



def _host(visibility="private"):
    return HostIngressEnvelope(
        NamespaceId("bot", "persona"), "platform", "private-conversation",
        "sender", "message-1", "Hello", 1.0, 2.0, visibility,
        SourceLineage("a" * 64, "reported", "message", "external_report",
                      "reported_claim"),
    )


def test_private_reply_source_requires_explicit_policy_and_exact_private_scope():
    policy = AdminD06PrivateReplySourcePolicy(1, "private_conversation", True)
    host = _host()
    assert source_admission_from_host(host).purposes == ("context", "consolidation")
    private = source_admission_from_host(host, policy)
    assert private.purposes == ("context", "consolidation", "expression")
    assert private.audiences == (host.conversation_ref,)
    assert source_admission_from_host(replace(host, visibility="group"), policy).purposes == (
        "context", "consolidation")
    with pytest.raises(ValueError):
        AdminD06PrivateReplySourcePolicy(1, "all_conversations", True)
