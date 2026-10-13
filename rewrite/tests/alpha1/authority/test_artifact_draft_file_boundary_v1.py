"""Real isolated byte observations; no Authority/admission qualification claim."""
import hashlib
import os

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d11_artifact_draft_executor_v1 import _readback
from sylanne3.runtime.d11_artifact_draft_contract_v1 import (
    DraftFileIdentityV1, DraftFileTargetV1, CHUNK_BYTES, MAX_DRAFT_BYTES,
)


def test_readback_does_not_attribute_another_same_name_same_hash_file(tmp_path):
    target = tmp_path / "draft.md"
    target.write_bytes(b"one actual draft\n")
    first = target.stat()
    identity = DraftFileIdentityV1(first.st_dev, first.st_ino)
    replacement = tmp_path / "replacement.md"
    replacement.write_bytes(target.read_bytes())
    os.replace(replacement, target)
    assert DraftFileIdentityV1(target.stat().st_dev, target.stat().st_ino) != identity
    with pytest.raises(AuthorityUnavailable, match="another same-name file identity"):
        _readback(target, expected_length=first.st_size,
            expected_digest=hashlib.sha256(b"one actual draft\n").hexdigest(), expected_identity=identity)


def test_actual_readback_obeys_the_frozen_byte_ceiling(tmp_path):
    target = tmp_path / "draft.md"
    data = b"x" * MAX_DRAFT_BYTES
    target.write_bytes(data)
    current = target.stat()
    meter = [0]
    observed = _readback(target, expected_length=len(data), expected_digest=hashlib.sha256(data).hexdigest(),
        expected_identity=DraftFileIdentityV1(current.st_dev, current.st_ino), read_meter=meter)
    assert observed == DraftFileIdentityV1(current.st_dev, current.st_ino)
    assert meter == [MAX_DRAFT_BYTES]
    meter = [0]
    with pytest.raises(AuthorityUnavailable, match="metadata length differs"):
        _readback(target, expected_length=CHUNK_BYTES, expected_digest=hashlib.sha256(data).hexdigest(), read_meter=meter)
    assert meter == [0]


@pytest.mark.parametrize("filename", ["../draft.md", "C:report.md", "draft.md:payload", "nested/draft.md", "CON", "draft.md."])
def test_registered_target_refuses_unscoped_filename(filename):
    with pytest.raises(ValueError, match="finite regular filename"):
        DraftFileTargetV1("draft-root", "installed-root", "a" * 64, DraftFileIdentityV1(1, 1),
            filename, "create", 0, None, None, None, MAX_DRAFT_BYTES)
