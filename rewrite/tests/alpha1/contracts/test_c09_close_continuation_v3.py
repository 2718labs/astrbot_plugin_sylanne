"""Actual OS lease remains continuously held across final-close continuation."""
import threading
import pytest
from sylanne3.authority_service.c09_storage_control_v1 import InstalledC09InstanceLeaseV1
from sylanne3.authority_service.contract import AuthorityUnavailable


def test_actual_lease_cannot_close_or_reacquire_inside_continuation(tmp_path):
    lease=InstalledC09InstanceLeaseV1(tmp_path/'instance.lock')
    entered=threading.Event();finished=threading.Event()
    def close():
        entered.set();lease.close();finished.set()
    with lease.hold_continuation_v3():
        with pytest.raises(AuthorityUnavailable):lease.close()
        thread=threading.Thread(target=close);thread.start();assert entered.wait(1)
        assert not finished.wait(0.05)
        lease.require_held()
        with pytest.raises(AuthorityUnavailable):InstalledC09InstanceLeaseV1(tmp_path/'instance.lock')
    thread.join(timeout=2);assert finished.is_set()
    with pytest.raises(AuthorityUnavailable):lease.require_held()
    fresh=InstalledC09InstanceLeaseV1(tmp_path/'instance.lock');fresh.close()
