"""Typed D09 visible-expression limit for natural reply candidates.

Compiling a draft does not activate it. W01 must read an active policy under
the same current graph fence as the natural reply before passing it to D09.
"""

from __future__ import annotations

from dataclasses import dataclass


EXPRESSION_POLICY_SCHEMA_V1 = "d09.expression_policy.v1"
DEFAULT_MAX_VISIBLE_CHARS_V1 = 2048


@dataclass(frozen=True, slots=True)
class D09ExpressionPolicyV1:
    policy_ref: str
    policy_version: str
    max_visible_chars: int
    schema: str = EXPRESSION_POLICY_SCHEMA_V1

    def __post_init__(self) -> None:
        if (type(self.policy_ref) is not str or not self.policy_ref.strip()
                or type(self.policy_version) is not str
                or not self.policy_version.strip()
                or self.schema != EXPRESSION_POLICY_SCHEMA_V1):
            raise ValueError("versioned D09 expression policy is required")
        if (type(self.max_visible_chars) is not int
                or not 1 <= self.max_visible_chars <= DEFAULT_MAX_VISIBLE_CHARS_V1):
            raise ValueError("max_visible_chars must be an integer in [1, 2048]")


def compile_expression_policy_v1(policy: D09ExpressionPolicyV1) -> D09ExpressionPolicyV1:
    """Return an exact, bounded candidate for D12 to digest and persist."""
    if type(policy) is not D09ExpressionPolicyV1:
        raise TypeError("typed D09 expression policy required")
    return policy


__all__ = (
    "EXPRESSION_POLICY_SCHEMA_V1", "DEFAULT_MAX_VISIBLE_CHARS_V1",
    "D09ExpressionPolicyV1", "compile_expression_policy_v1",
)
