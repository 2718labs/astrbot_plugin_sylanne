"""A route-bound grant cannot enter the legacy installed admission path."""

from dataclasses import asdict
import json

import pytest

from sylanne3.runtime.installed_dispatch_admission_issuer import (
    DispatchAdmissionHold, InstalledDispatchAdmissionIssuer,
)

from test_installed_dispatch_admission_issuer import _case
from test_post_c02_reply_bundle_v2 import _inputs


def test_route_bound_grant_requires_coordinator_final_reissue():
    db, _, _, candidate = _case()
    try:
        grant = _inputs()["pre_frozen_grant"]
        assert grant.route_binding_digest is not None
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)", (
            candidate.grant_ref, "bot", "persona", 1,
            json.dumps(asdict(grant)), 1,
        ))
        with pytest.raises(DispatchAdmissionHold) as error:
            InstalledDispatchAdmissionIssuer().issue_dispatch_admission(
                None, None, candidate, db,
                graph_incarnation="incarnation:one", now_utc=1.0)
        assert error.value.missing == ("dispatch.post_c02_final_reissue_required",)
    finally:
        db.close()
