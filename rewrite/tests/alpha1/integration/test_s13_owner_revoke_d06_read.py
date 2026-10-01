"""S13 slice: Owner withdrawal blocks D06's current source read.

The graph/coordinator are production classes. The Authority Owner port is a
controlled in-process fixture; model and final dispatch are not exercised.
"""

from uuid import uuid4

from tests.alpha1.d12.test_owner_graph_lease import owner_graph  # noqa: F401
from tests.alpha1.runtime.test_source_access_revocation_owner_v1 import _case

from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
from sylanne3.memory_repository import MemoryRepository


def test_owner_revoke_blocks_later_d06_read_without_erasing_source(owner_graph):
    graph, coordinator, _port, authority, lease, source, access = _case(owner_graph)
    repository = MemoryRepository(graph, "bot", "persona")
    before, proof_before = repository.read_source_evidence(
        "source-1", audience="owner", purpose="context")
    assert before is not None and before.text == "private"
    assert {version.key for version in proof_before.versions} >= {source, access}

    request = SourceAccessRevocationRequest(
        "source-1", "owner-session", str(uuid4()), 3.0)
    receipt = coordinator.revoke_source_access_v1(authority, lease, request)
    assert receipt.access_revision == 2
    assert receipt.access_epoch > 0

    current, proof_after = repository.read_source_evidence(
        "source-1", audience="owner", purpose="context")
    assert current is None
    versions = {version.key: version.revision for version in proof_after.versions}
    assert versions[source] == 1 and versions[access] == 2
    assert graph._db.execute(
        "SELECT revision,valid FROM graph_atoms WHERE token=?", (source.token,),
    ).fetchone() == (1, 1)
    assert coordinator.revoke_source_access_v1(authority, lease, request) == receipt
