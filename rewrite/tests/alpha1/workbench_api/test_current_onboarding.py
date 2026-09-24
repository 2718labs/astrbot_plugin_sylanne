from sylanne3.workbench_api.current_onboarding import CurrentOnboardingResolver


class D01:
    def __init__(self):
        self.calls = []

    def resolve_create_character(self, **kwargs):
        self.calls.append(kwargs)
        return "d01-result"

    def replay_committed_create_character(self, **kwargs):
        self.calls.append(("replay", kwargs))
        return "d01-receipt"

    def reject_unresolvable_create_character(self, **kwargs):
        self.calls.append(("reject", kwargs))
        return True


class D03:
    def __init__(self):
        self.calls = []

    def resolve_bind_scene(self, **kwargs):
        self.calls.append(kwargs)
        return "d03-result"

    def replay_committed_bind_scene(self, **kwargs):
        self.calls.append(("replay", kwargs))
        return "d03-receipt"


def test_create_and_bind_are_delegated_to_their_domain_resolver():
    d01, d03 = D01(), D03()
    resolver = CurrentOnboardingResolver(d01=d01, d03=d03)
    common = {
        "session": "session",
        "scope": "bot/persona",
        "purpose": "purpose",
        "audience": "audience",
        "operation_id": "operation",
        "request_digest": "digest",
    }
    create = {**common, "input_data": {"name": "x"}}
    bind = {**common, "input_data": {"scene_ref": "scene:x"}}

    assert resolver.resolve_create_character(**create) == "d01-result"
    assert resolver.resolve_bind_scene(coordinator="graph", **bind) == "d03-result"
    assert d01.calls == [create]
    assert d03.calls == [{"coordinator": "graph", **bind}]


def test_missing_domain_resolver_preserves_hold():
    d01, d03 = D01(), D03()
    assert CurrentOnboardingResolver(d01=d01).resolve_bind_scene(
        coordinator="graph", session="session", scope="bot/persona",
        purpose="purpose", audience="audience", operation_id="operation",
        request_digest="digest", input_data={},
    ) is None
    assert CurrentOnboardingResolver(d03=d03).resolve_create_character(
        session="session", scope="bot/persona", purpose="purpose",
        audience="audience", operation_id="operation", request_digest="digest",
        input_data={},
    ) is None
    assert d01.calls == []
    assert d03.calls == []


def test_replay_and_pending_rejection_are_delegated_without_reselection():
    d01, d03 = D01(), D03()
    resolver = CurrentOnboardingResolver(d01=d01, d03=d03)
    args = {
        "coordinator": "graph", "session": "signed-session", "scope": "bot/persona",
        "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": "operation", "request_digest": "digest",
    }
    assert resolver.replay_committed_create_character(**args) == "d01-receipt"
    assert resolver.reject_unresolvable_create_character(**args) is True
    assert resolver.replay_committed_bind_scene(**args) == "d03-receipt"
    assert d01.calls == [("replay", args), ("reject", args)]
    assert d03.calls == [("replay", args)]
    assert CurrentOnboardingResolver(d03=d03).replay_committed_create_character(**args) is None
    assert CurrentOnboardingResolver(d03=d03).reject_unresolvable_create_character(**args) is False
    assert CurrentOnboardingResolver(d01=d01).replay_committed_bind_scene(**args) is None
