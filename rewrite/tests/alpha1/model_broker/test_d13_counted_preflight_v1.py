"""Transient non-authorizing preflight/current recheck, no real provider call."""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
import shlex

import pytest
from test_installed_d13_wire_evidence_v1 import setup, reserve
from sylanne3.runtime.installed_d13_natural_frame_v4 import (
    D13NaturalWirePreflightV1, freeze_current_natural_frame_v4,
    prepare_current_natural_wire_preflight_v1,
)
from sylanne3.authority_service.d13_installed_counter_v1 import InstalledD13CounterCommandV1


def preflight(c):
    c["port"]._last_pair = None
    value = prepare_current_natural_wire_preflight_v1(c["db"], **c["args"], installed_wire_port=c["port"])
    assert type(value) is D13NaturalWirePreflightV1
    assert value.status == "non_authorizing_preflight"
    assert c["port"]._last_pair is None  # No installed selection/admission happened.
    return value


def test_later_current_read_reconstructs_counted_pair_with_old_serialization_time(monkeypatch):
    c = setup(monkeypatch)
    before = c["db"].total_changes
    pending = preflight(c)
    assert c["db"].total_changes == before
    observed_now = []
    import sylanne3.runtime.installed_d13_natural_frame_v4 as frame
    read = frame.read_current_d13_window_for_authority_v1
    def observe(*a, **kw):
        observed_now.append(a[5])
        return read(*a, **kw)
    monkeypatch.setattr(frame, "read_current_d13_window_for_authority_v1", observe)
    selected, reads, decision = freeze_current_natural_frame_v4(c["db"], **dict(c["args"], now_utc=101.0),
        installed_wire_port=c["port"], preflight=pending)
    assert observed_now == [101.0]
    assert selected == pending.compressed
    assert selected.input.frozen_at_utc == 100.0
    assert decision.budget_state == "preparation_only"
    assert decision.activation_expected.revision == pending.cache_ref.version == 1
    assert selected.input.history_selection.block_ref.version == 2
    c.update(selected=selected, reads=reads, decision=decision)
    binding = reserve(c)
    admitted = c["port"].validate_reserved_selection_v1(selected=selected, decision=decision,
        binding=binding, read_versions=reads, now_utc=101.0)
    assert admitted.budget_state == "reserved_original"


@pytest.mark.parametrize("change", ["source", "access", "deletion", "generation", "cache", "expired", "future", "policy"])
def test_counted_pair_cannot_replay_stale_current_eligibility(monkeypatch, change):
    c = setup(monkeypatch)
    pending = preflight(c)
    now = 101.0
    if change == "source":
        w = c["state"]["window"]
        c["state"]["window"] = replace(w, turns=(replace(w.turns[0], text="changed source"), *w.turns[1:]))
    elif change in {"access", "deletion", "generation"}:
        field = {"access": "access_epoch", "deletion": "delete_epoch", "generation": "activation_epoch"}[change]
        w = c["state"]["window"]
        c["state"]["window"] = replace(w, **{field: getattr(w, field) + 1})
    elif change == "cache":
        c["db"].execute("UPDATE graph_atoms SET revision=revision+1 WHERE token=?", (pending.cache_ref.ref,))
    elif change == "expired":
        now = pending.expires_at_utc
    elif change == "future":
        now = pending.frozen_at_utc - 1
    else:
        pending = replace(pending, installed_policy_digest="e" * 64)
    with pytest.raises(ValueError):
        freeze_current_natural_frame_v4(c["db"], **dict(c["args"], now_utc=now),
            installed_wire_port=c["port"], preflight=pending)


def test_uncommitted_preflight_cannot_be_used_as_saved_original(monkeypatch):
    c = setup(monkeypatch)
    pending = preflight(c)
    with pytest.raises(ValueError, match="preflight scope"):
        freeze_current_natural_frame_v4(c["db"], **c["args"], installed_wire_port=c["port"],
            preflight=pending, original=pending.compressed)


def test_fixed_counter_process_returns_only_matching_signed_original(monkeypatch, tmp_path):
    c = setup(monkeypatch)
    pending = preflight(c)
    from sylanne3.authority_service.d13_wire_evidence_v1 import d13_full_wire_count_request_v1
    request = d13_full_wire_count_request_v1(policy=c["policy"], raw=pending.raw,
        compressed=pending.compressed, current_window=pending.current_window,
        standby=pending.standby, precompression_plan=pending.precompression_plan)
    # Synthetic offline counter: the test parent signed the exact response
    # with an ephemeral key. No private key is written into the program.
    executable = tmp_path / "offline-counter"
    executable.write_text("#!/bin/sh\nprintf '%s' " + shlex.quote(json.dumps(c["envelope"])))
    executable.chmod(0o700)
    @contextmanager
    def fixture_owned_file(path):
        fd = os.open(path, os.O_RDONLY)
        try:
            yield fd
        finally:
            os.close(fd)
    import sylanne3.authority_service.d13_installed_counter_v1 as counter
    # Only installation ownership is replaced for this temporary test asset;
    # program SHA, bounded process, exact pair and signature checks are real.
    monkeypatch.setattr(counter, "opened_installed_file_v1", fixture_owned_file)
    command = InstalledD13CounterCommandV1(str(executable), hashlib.sha256(executable.read_bytes()).hexdigest(), 2)
    c["db"].commit()
    assert command.count_outside_graph_transaction_v1(db=c["db"], policy=c["policy"], request=request) == c["envelope"]
    executable.write_text("#!/bin/sh\nprintf bad")
    with pytest.raises(ValueError, match="program changed"):
        command.count_outside_graph_transaction_v1(db=c["db"], policy=c["policy"], request=request)
