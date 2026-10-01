"""Controlled same-Core pairing method; OS installation lock remains a cold test."""

from datetime import datetime, timezone
import threading

import pytest

from rewrite.tests.alpha1.authority.test_installed_creation_ticket_verifier import original
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.daemon import AuthorityDaemon
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource


def test_pinned_creation_original_and_pairing_share_offline_maintenance_boundary(original):
    _, core, ticket, verifier = original
    pairings = AuthorityOwnerPairingSource(
        core, utc_clock=lambda: datetime.now(timezone.utc), create=True)
    daemon = object.__new__(AuthorityDaemon)
    daemon.core = core
    daemon.owner_pairings = pairings
    daemon._creation_verifier = verifier
    daemon._maintenance_lock = threading.RLock()
    daemon._lock_handle = object()  # Method scope only, not an OS lock claim.
    daemon._closed = daemon._starting = False
    daemon._listener = None
    namespace = namespace_ref(ticket.namespace)
    kwargs = dict(
        administrator_credential="admin", authority_namespace=namespace,
        ticket=ticket, client_certificate_sha256="a" * 64,
        valid_until_utc=datetime(2098, 1, 1, tzinfo=timezone.utc))

    with pytest.raises(AuthorityUnavailable, match="expiry"):
        daemon.pair_original_creation_ticket(**{
            **kwargs, "valid_until_utc": datetime(2100, 1, 1, tzinfo=timezone.utc)})
    assert pairings.current_creation_pairing(namespace) is None
    daemon.pair_original_creation_ticket(**kwargs)
    assert pairings.current_creation_pairing(namespace).ticket == ticket
    with pytest.raises(AuthorityUnavailable, match="already exists"):
        daemon.pair_original_creation_ticket(**kwargs)
    daemon._listener = object()
    with pytest.raises(AuthorityUnavailable, match="offline"):
        daemon.verify_original_creation_ticket(ticket)
