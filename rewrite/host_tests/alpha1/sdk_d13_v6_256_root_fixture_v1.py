"""Fresh-only finite Root request for the 256 actual SDK dialogue fixture.

These are initial authorization totals, never measured usage. The SDK still
creates the named persona, observes its real identity, and binds namespace
before the ordinary installer signs anything. Existing requests are unchanged.
"""

SCENARIO = "sdk_d13_v6_256_current_v1"
PROFILE_ID = "sdk-d13-v6-256"
EXPECTED_INITIAL_PERSONA_ID = "sdk-d13-v6-256-persona"
EPISODE_COUNT = 256
MAX_EPISODE_CALLS = 6
MAX_AUXILIARY_CALLS = 2
MAX_TOTAL_MODEL_CALLS = EPISODE_COUNT * 6  # Encode/appraisal/routing/generation/review plus at most one actual background D13 call.
PER_EPISODE_MODEL_LIMITS = {
    "input_tokens": 48000, "output_tokens": 8000,
    "model_tokens": 56000, "model_microusd": 1200,
}
INITIAL_MODEL_LIMITS = {dimension: quantity * EPISODE_COUNT
                        for dimension, quantity in PER_EPISODE_MODEL_LIMITS.items()}


def approved_sdk_d13_v6_256_initial_request_v1(*, executable_sha256, valid_until_utc):
    """Use only before SDK probing and first installation in the new scenario."""
    from rewrite.host_tests.alpha1.sdk_m1_fixture_contract_v1 import approved_initial_request_v1
    from scripts.alpha1.install_linux import check_request

    value = approved_initial_request_v1(executable_sha256=executable_sha256,
                                        valid_until_utc=valid_until_utc)
    assert value["schema"] == "sylanne3.linux-install-request.v4"
    assert all(value["budget_limits"][dimension] == quantity
               for dimension, quantity in PER_EPISODE_MODEL_LIMITS.items())
    maximum = dict(value["budget_max_ceiling"])
    quote = dict(value["model_quote"])
    local_quote = dict(value["local_quote"])
    value.update(profile_id=PROFILE_ID, persona_id=EXPECTED_INITIAL_PERSONA_ID)
    value["budget_limits"].update(INITIAL_MODEL_LIMITS)
    # One Root; actual terminal retirement handles the unchanged 512-item census.
    # D13's per-episode call is within the original bounded physical/auxiliary
    # allowance. The current-window four-block cap is not a paid-call quota.
    assert value["budget_max_ceiling"] == maximum
    assert value["model_quote"] == quote and value["local_quote"] == local_quote
    assert value["budget_valid_until_utc"] == valid_until_utc
    return check_request(value)
