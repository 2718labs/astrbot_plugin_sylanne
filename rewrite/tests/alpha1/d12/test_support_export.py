"""Unit checks for the bounded local manifest writer; no product grant claim."""

from hashlib import sha256
import json
from uuid import uuid4

import pytest

from sylanne3.workbench_api.support_export import write_view_status_export_v1


def test_view_status_export_only_keeps_allowlisted_fields_and_hashes(tmp_path):
    operation_id = str(uuid4())
    workspace = {
        "namespace": {"bot": "bot", "persona": "persona"},
        "access_generation": 3,
        "view_diagnostics": ({
            "view_type": "memory", "read_status": "unavailable",
            "problem_code": "secret-source-identity",
            "private_original": "must-not-leak",
        },),
        "data": {"raw_text": "must-not-leak"},
    }
    receipt = write_view_status_export_v1(
        root=tmp_path, operation_id=operation_id,
        scope="bot/persona", workspace=workspace)
    encoded = (tmp_path / f"{operation_id}.json").read_bytes()
    manifest = json.loads(encoded)
    assert receipt["manifest_sha256"] == sha256(encoded).hexdigest()
    assert manifest["payload_sha256"] == receipt["payload_sha256"]
    assert manifest["view_status"] == [{
        "view_type": "memory", "read_status": "unavailable"}]
    assert b"must-not-leak" not in encoded
    assert b"secret-source-identity" not in encoded
    assert write_view_status_export_v1(
        root=tmp_path, operation_id=operation_id,
        scope="bot/persona", workspace=workspace) == receipt

    workspace["access_generation"] = 4
    with pytest.raises(ValueError, match="different current snapshot"):
        write_view_status_export_v1(
            root=tmp_path, operation_id=operation_id,
            scope="bot/persona", workspace=workspace)


def test_view_status_export_rejects_path_like_operation_and_untrusted_state(tmp_path):
    workspace = {"namespace": {"bot": "bot", "persona": "persona"},
                 "access_generation": 1, "view_diagnostics": ()}
    with pytest.raises(ValueError, match="canonical support operation"):
        write_view_status_export_v1(
            root=tmp_path, operation_id="../escape", scope="bot/persona",
            workspace=workspace)
    with pytest.raises(ValueError, match="invalid current view diagnostic"):
        write_view_status_export_v1(
            root=tmp_path, operation_id=str(uuid4()), scope="bot/persona",
            workspace={"namespace": {"bot": "bot", "persona": "persona"},
                       "access_generation": 1, "view_diagnostics": (
                {"view_type": "memory", "read_status": "ready", "coverage": []},
            )})
