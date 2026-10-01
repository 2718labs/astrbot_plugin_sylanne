"""Deterministic, synthetic GraphStore software-scale probe for G6.

Run each size in a fresh process. This exercises the real GraphStore commit,
snapshot and paginated-query code, without claiming Authority admission,
production GraphCoordinator permissions, model quality, or real provider cost.
No data is retained unless the caller explicitly requests a JSON report.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from time import perf_counter_ns

import psutil

from sylanne3.contracts import Event, Scope, canonical_json
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import (
    AtomKey, GraphCandidate, GraphVersion, GraphWrite, Owner, TypeRegistry,
    TypeSpec,
)


TYPE_NAME = "g6.synthetic_source.v1"
BOT = "g6-probe-bot"
PERSONA = "g6-probe-persona"
SCOPE = Scope(BOT, PERSONA, "g6-synthetic")
OWNER = Owner("persona", BOT, PERSONA)
BATCH = 128
PAGE = 128
PROBE_READS = 64
SIZES = (1_000, 10_000, 100_000)
MEMORY_RESERVE = {1_000: 256, 10_000: 512, 100_000: 1_024}
DISK_RESERVE = {1_000: 64, 10_000: 256, 100_000: 1_024}


def _source_key(index: int) -> AtomKey:
    return AtomKey(OWNER, TYPE_NAME, f"source-{index:06d}")


def _source_value(index: int, revision: int = 1) -> dict:
    return {
        "source_id": f"source-{index:06d}",
        "day": index % 7,
        "revision": revision,
        "text": "synthetic-local-source-" + f"{index:06d}" + "x" * 32,
    }


def _validate_source(value: dict) -> None:
    if (type(value) is not dict or set(value) != {
            "source_id", "day", "revision", "text"}
            or type(value["source_id"]) is not str
            or type(value["day"]) is not int or not 0 <= value["day"] < 7
            or value["revision"] not in (1, 2)
            or type(value["text"]) is not str):
        raise ValueError("invalid synthetic source")


def _registry() -> TypeRegistry:
    registry = TypeRegistry()
    registry.register(TypeSpec(
        TYPE_NAME, ("persona",), "source", _validate_source,
        schema_version=1, writer_domain="d06",
        schema_hash=hashlib.sha256(b"g6.synthetic_source.v1").hexdigest()))
    return registry


def _percentiles(samples_ns: list[int]) -> dict[str, float | int]:
    values = sorted(samples_ns)
    if not values:
        raise ValueError("timing sample is empty")
    return {
        "samples": len(values),
        "p50_ms": round(values[math.ceil(.50 * len(values)) - 1] / 1_000_000, 3),
        "p95_ms": round(values[math.ceil(.95 * len(values)) - 1] / 1_000_000, 3),
        "max_ms": round(values[-1] / 1_000_000, 3),
    }


def _fingerprint() -> dict:
    rewrite = Path(__file__).resolve().parents[3]
    source_paths = (
        rewrite / "sylanne3" / "graph_store.py",
        rewrite / "sylanne3" / "graph_types.py",
        rewrite / "sylanne3" / "store.py",
        Path(__file__).resolve(),
    )
    source_hashes = {
        str(path.relative_to(rewrite)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in source_paths
    }
    package_manifest = rewrite.parent / "metadata.yaml"
    try:
        git_head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=rewrite.parent,
            text=True, timeout=5).strip()
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=rewrite.parent, text=True, timeout=10).strip())
    except (OSError, subprocess.SubprocessError):
        git_head, dirty = None, None
    try:
        executable_sha256 = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    except OSError:
        # WindowsApps Python aliases can execute while denying binary reads.
        executable_sha256 = None
    return {
        "python_version": sys.version,
        "python_executable": str(Path(sys.executable).resolve()),
        "python_executable_sha256": executable_sha256,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "logical_cpu_count": psutil.cpu_count(logical=True),
        "total_memory_mib": round(psutil.virtual_memory().total / 1_048_576, 1),
        "pid": os.getpid(),
        "sqlite_version": sqlite3.sqlite_version,
        "psutil_version": psutil.__version__,
        "git_head": git_head,
        "tracked_tree_dirty": dirty,
        "source_sha256": source_hashes,
        "metadata_yaml_sha256": (hashlib.sha256(package_manifest.read_bytes()).hexdigest()
                                 if package_manifest.is_file() else None),
        "frozen_package_sha256": None,
    }


def _timed(bucket: list[int], operation):
    started = perf_counter_ns()
    result = operation()
    bucket.append(perf_counter_ns() - started)
    return result


def run(size: int) -> dict:
    if size not in SIZES:
        raise ValueError("size must be one of 1k, 10k, 100k")
    available = psutil.virtual_memory().available
    disk_free = shutil.disk_usage(tempfile.gettempdir()).free
    preflight = {
        "available_memory_mib": round(available / 1_048_576, 1),
        "free_disk_mib": round(disk_free / 1_048_576, 1),
        "minimum_available_memory_mib": MEMORY_RESERVE[size],
        "minimum_free_disk_mib": DISK_RESERVE[size],
    }
    report = {
        "schema": "sylanne3.g6.synthetic-graph-scale.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "resource_hold",
        "scope": "synthetic GraphStore software baseline only",
        "size": size,
        "generator": "index-arithmetic-v1",
        "batch_size": BATCH,
        "page_size": PAGE,
        "preflight": preflight,
        "fingerprint": _fingerprint(),
    }
    if (available < MEMORY_RESERVE[size] * 1_048_576
            or disk_free < DISK_RESERVE[size] * 1_048_576):
        return report

    process = psutil.Process()
    total_started = perf_counter_ns()
    ingest, duplicate, correction = [], [], []
    key_read, cross_day_read, page_query = [], [], []
    dataset_hash = hashlib.sha256()
    candidate_samples: list[GraphCandidate] = []
    replay_count = max(10, size // 1_000)
    correction_count = size // 100
    with tempfile.TemporaryDirectory(prefix="sylanne-g6-") as directory:
        db_path = Path(directory) / "graph.db"
        store = GraphStore(db_path, _registry())
        try:
            for start in range(0, size, BATCH):
                end = min(start + BATCH, size)
                keys = tuple(_source_key(index) for index in range(start, end))
                writes = tuple(GraphWrite(key, _source_value(index))
                               for index, key in zip(range(start, end), keys))
                for write in writes:
                    dataset_hash.update(canonical_json(write.value).encode("utf-8"))
                    dataset_hash.update(b"\n")
                candidate = GraphCandidate(
                    Event(SCOPE, f"ingest-{start:06d}", float(start + 1),
                          "g6.synthetic.ingest", {"start": start, "end": end}),
                    tuple(GraphVersion(key, 0) for key in keys), writes)
                receipt = _timed(ingest, lambda: store.graph_commit(candidate))
                assert receipt.status == "committed"
                if len(candidate_samples) < 64:
                    candidate_samples.append(candidate)

            for index in range(replay_count):
                receipt = _timed(duplicate, lambda index=index:
                                 store.graph_commit(candidate_samples[
                                     index % len(candidate_samples)]))
                assert receipt.status == "duplicate"

            corrected = []
            for index in range(correction_count):
                source_index = (index * 97) % size
                key = _source_key(source_index)
                prior = store.graph_snapshot((key,)).get(key)
                assert prior is not None and prior.revision == 1 and prior.valid
                candidate = GraphCandidate(
                    Event(SCOPE, f"correct-{source_index:06d}",
                          float(size + index + 1), "g6.synthetic.correction",
                          {"source_index": source_index}),
                    (GraphVersion(key, 1),),
                    (GraphWrite(key, _source_value(source_index, 2)),))
                receipt = _timed(correction, lambda: store.graph_commit(candidate))
                assert receipt.status == "committed"
                corrected.append(source_index)

            for index in range(PROBE_READS):
                key = _source_key((index * 7919) % size)
                snapshot = _timed(
                    key_read, lambda key=key: store.graph_snapshot((key,)))
                assert snapshot.get(key) is not None and snapshot.get(key).valid

                days = tuple(
                    _source_key(day + 7 * ((index * 13) %
                        (((size - 1 - day) // 7) + 1)))
                    for day in range(7))
                snapshot = _timed(
                    cross_day_read,
                    lambda days=days: store.graph_snapshot(days))
                assert {snapshot.get(key).value["day"] for key in days} == set(range(7))

            after = None
            expected_epoch = None
            for _ in range(PROBE_READS):
                page = _timed(page_query, lambda after=after, epoch=expected_epoch:
                              store.graph_query(
                                  BOT, PERSONA, type_names=(TYPE_NAME,),
                                  after=after, limit=PAGE, expected_epoch=epoch))
                assert page.snapshot.atoms
                expected_epoch = page.snapshot.epochs[0]
                after = page.next_after
                if after is None:
                    expected_epoch = None

            with store._lock:
                atoms = store._db.execute(
                    "SELECT COUNT(*) FROM graph_atoms WHERE bot=? AND persona=?",
                    (BOT, PERSONA)).fetchone()[0]
                events = store._db.execute(
                    "SELECT COUNT(*) FROM graph_events WHERE bot=? AND persona=?",
                    (BOT, PERSONA)).fetchone()[0]
            assert atoms == size
            assert events == math.ceil(size / BATCH) + correction_count
            assert len(set(corrected)) == correction_count
        finally:
            store.close()
        db_bytes = sum(path.stat().st_size for path in directory_path_files(db_path))

    report.update({
        "status": "completed",
        "dataset_sha256": dataset_hash.hexdigest(),
        "workload": {
            "sources": size,
            "ingest_batches": math.ceil(size / BATCH),
            "duplicate_event_replays": replay_count,
            "corrections": correction_count,
            "single_key_reads": PROBE_READS,
            "seven_day_snapshot_reads": PROBE_READS,
            "page_queries": PROBE_READS,
        },
        "measurements": {
            "ingest_batch": _percentiles(ingest),
            "duplicate_event": _percentiles(duplicate),
            "correction": _percentiles(correction),
            "single_key_read": _percentiles(key_read),
            "seven_day_snapshot": _percentiles(cross_day_read),
            "page_query": _percentiles(page_query),
            "elapsed_seconds": round((perf_counter_ns() - total_started) / 1e9, 3),
            "peak_process_working_set_mib": round(
                getattr(process.memory_info(), "peak_wset", process.memory_info().rss)
                / 1_048_576, 1),
            "graph_database_bytes": db_bytes,
        },
        "assertions": {"atom_count": atoms, "event_count": events,
                       "corrected_unique": len(set(corrected))},
    })
    return report


def directory_path_files(db_path: Path) -> tuple[Path, ...]:
    return tuple(path for path in (db_path, Path(str(db_path) + "-wal"),
                                   Path(str(db_path) + "-shm")) if path.exists())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, choices=SIZES, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run(args.size)
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output is None:
        sys.stdout.write(encoded)
    else:
        args.output.write_text(encoded, encoding="utf-8")
    return 0 if report["status"] == "completed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
