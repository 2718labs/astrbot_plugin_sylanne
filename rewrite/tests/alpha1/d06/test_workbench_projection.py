import pytest

from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.domain_registry import discover_domain_registry
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import InterpretationRecord, SourceRecord
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId
from sylanne3.workbench_api.domain_registry import ProjectionContextV1
from sylanne3.workbench_api.domain_registry import CurrentDomainViewRegistry


def context(*, audience="owner", purpose="context"):
    authority = AuthorityContext(
        "actor", "d12", "capability", NamespaceId("bot", "persona"),
        ("event",), purpose, (audience,), "policy", 3,
    )
    return ProjectionContextV1(authority, audience, purpose)


def source(source_id="s1", *, audiences=("owner",), purposes=("context",)):
    return SourceRecord(
        source_id, "private original text", "speaker-secret", "reported", "reported",
        None, 1.0, "private-provenance", audiences, purposes,
    ).to_dict()


def access(source_id="s1", *, status="active", audiences=("owner",), purposes=("context",)):
    return {"source_id": source_id, "audiences": list(audiences),
            "purposes": list(purposes), "status": status, "recorded_at": 1.0}


def atom(kind, value):
    if kind == "memory.source":
        subject, name = value["source_id"], "record"
    elif kind == "memory.access":
        subject, name = value["source_id"], "access"
    else:
        subject, name = value["interpretation_id"], "current"
    key = AtomKey(Owner("event", "bot", "persona", subject), kind, name)
    return {"key": key.token, "type": kind, "name": name, "revision": 1, "value": value}


def test_projection_exposes_only_authorized_source_metadata_and_no_private_text():
    result = D06DomainProvider.project_workbench(
        "d06.memory_sources.v1",
        (atom("memory.source", source()), atom("memory.access", access("s1"))),
        context=context(),
    )
    assert result == {
        "sources": [{"source_id": "s1", "source_kind": "reported",
                     "assertion_status": "reported", "recorded_at": 1.0,
                     "qualification": "not_recorded"}],
        "coverage": "complete",
    }
    assert "private original text" not in repr(result)
    assert "speaker-secret" not in repr(result)
    assert "private-provenance" not in repr(result)


@pytest.mark.parametrize("access_value", [
    access("s1", status="withdrawn"),
    access("s1", audiences=("other",)),
    access("s1", purposes=("audit",)),
])
def test_projection_hides_withdrawn_or_context_mismatched_sources(access_value):
    result = D06DomainProvider.project_workbench(
        "d06.memory_sources.v1",
        (atom("memory.source", source()), atom("memory.access", access_value)),
        context=context(),
    )
    assert result["sources"] == []


def test_projection_hides_retracted_source_and_fails_on_missing_access_or_source():
    retracted = InterpretationRecord("i1", ("s1",), "subject", "private claim",
                                     "retracted", 1.0, 2.0).to_dict()
    result = D06DomainProvider.project_workbench(
        "d06.memory_sources.v1",
        (atom("memory.source", source()), atom("memory.access", access("s1")),
         atom("memory.interpretation", retracted)), context=context(),
    )
    assert result["sources"] == []

    with pytest.raises(ValueError, match="source/access closure"):
        D06DomainProvider.project_workbench(
            "d06.memory_sources.v1", (atom("memory.source", source()),), context=context(),
        )
    with pytest.raises(ValueError, match="source/access closure"):
        D06DomainProvider.project_workbench(
            "d06.memory_sources.v1", (atom("memory.access", access("s1")),), context=context(),
        )


def test_projection_rejects_full_page_because_issuer_hides_truncation():
    full_page = tuple(atom("memory.source", source(f"s{i}")) for i in range(100))
    with pytest.raises(ValueError, match="completeness is not proven"):
        D06DomainProvider.project_workbench(
            "d06.memory_sources.v1", full_page, context=context(),
        )


def test_projection_requires_atom_identity_to_bind_values_to_owner_keys():
    raw = atom("memory.source", source())
    del raw["key"]
    with pytest.raises(ValueError, match="canonical atom identity"):
        D06DomainProvider.project_workbench(
            "d06.memory_sources.v1", (raw, atom("memory.access", access("s1"))),
            context=context(),
        )


def test_projection_rejects_value_key_identity_mismatch():
    raw = atom("memory.source", source())
    raw["key"] = AtomKey(Owner("event", "bot", "persona", "other"),
                          "memory.source", "record").token
    with pytest.raises(ValueError, match="identity does not match graph key"):
        D06DomainProvider.project_workbench(
            "d06.memory_sources.v1", (raw, atom("memory.access", access("s1"))),
            context=context(),
        )


def test_projection_contract_uses_same_event_owned_current_snapshot_types():
    contract = D06DomainProvider().workbench_view_contract["d06.memory_sources.v1"]
    assert contract["types"] == (
        "memory.source", "memory.access", "memory.interpretation",
    )
    assert contract["projection_context"] == "d12.projection_context.v1"


def test_live_domain_registry_exposes_only_declared_d06_projection():
    authority = context().authority
    registry = CurrentDomainViewRegistry(discover_domain_registry)
    catalogue = registry.catalogue(authority)
    assert catalogue.available["d06.memory_sources.v1"] == (
        "memory.source", "memory.access", "memory.interpretation",
    )
    projected = registry.project_workbench(
        authority, "d06.memory_sources.v1",
        (atom("memory.source", source()), atom("memory.access", access("s1"))),
        audience="owner", purpose="context",
    )
    assert projected["sources"][0]["source_id"] == "s1"
