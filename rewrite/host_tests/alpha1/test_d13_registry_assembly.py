"""D13 is visible to the production catalogue with its real cache type."""

from sylanne3.domain_registry import REQUIRED_DOMAINS, discover_domain_registry
from sylanne3.domains.d13 import D13ShortContextProvider


def test_d13_registers_a_concrete_cache_type_without_claiming_writes():
    registry = discover_domain_registry()
    assert len(REQUIRED_DOMAINS) == 13
    registration = registry.registrations["d13"]
    assert "d13" not in registry.unavailable
    assert type(registration.provider) is D13ShortContextProvider
    assert registration.proposal_schema == "d13.proposal.v1"
    assert registration.proposal_schema_hash == (
        registration.provider.descriptor.request_schema_hash)
    assert len(registration.type_specs) == 1
    spec = registration.type_specs[0]
    assert (spec.name, spec.writer_domain, spec.storage_role) == (
        "d13.compressed_turn_block.v2", "d13", "cache")
