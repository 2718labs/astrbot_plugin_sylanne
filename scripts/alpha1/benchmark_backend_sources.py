"""Bounded, synthetic GraphStore source benchmark; never a product OPS-08 pass.

Default invocation runs only 100 sources. The 1k/10k/100k ladder requires
--full, and every case has time, RSS and database-size ceilings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import sqlite3
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "rewrite")]

from sylanne3.contracts import Event, Scope  # noqa: E402
from sylanne3.domain_registry import discover_domain_registry  # noqa: E402
from sylanne3.graph_store import GraphStore  # noqa: E402
from sylanne3.graph_types import GraphCandidate, GraphVersion, GraphWrite  # noqa: E402
from sylanne3.memory_types import SourceRecord, source_key  # noqa: E402
from scripts.alpha1.generate_catalogue import _load_active_scheme  # noqa: E402


def _source_identity() -> dict:
    files = sorted((ROOT / "rewrite/sylanne3").rglob("*.py"))
    files.append(Path(__file__).resolve())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return {"algorithm": "sha256-path-and-content-v1", "file_count": len(files),
            "digest": digest.hexdigest()}


def _rss_bytes() -> int | None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t)]
        value = Counters()
        value.cb = ctypes.sizeof(value)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE,
                                               ctypes.POINTER(Counters), wintypes.DWORD]
        if psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(value), value.cb):
            return int(value.PeakWorkingSetSize)
        return None
    try:
        import resource
        used = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(used * (1 if sys.platform == "darwin" else 1024))
    except (ImportError, OSError):
        return None


def _physical_memory_bytes() -> int | None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
        return None
    try:
        return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError):
        return None


def _database_bytes(database: Path) -> int:
    return sum(path.stat().st_size for path in (
        database, Path(str(database) + "-wal"), Path(str(database) + "-shm")) if path.exists())


def _percentiles(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    ordered = sorted(values)
    return {"count": len(ordered), "p50_ms": ordered[(50 * len(ordered) + 99) // 100 - 1],
            "p95_ms": ordered[(95 * len(ordered) + 99) // 100 - 1],
            "max_ms": ordered[-1]}


def _source(seed: int, index: int, rng: random.Random) -> tuple:
    source_id = f"bench-{seed:08x}-{index:08d}"
    record = SourceRecord(
        source_id=source_id,
        text=f"Synthetic source {index}: " + " ".join(
            f"{rng.getrandbits(32):08x}" for _ in range(16)),
        speaker_id="benchmark", source_kind="simulated",
        assertion_status="unknown", occurred_at=float(index),
        recorded_at=float(index), provenance_root=f"synthetic:{source_id}",
        audiences=(), purposes=("audit",), parent_source_ids=(),
    )
    return source_key("benchmark-bot", "benchmark-persona", source_id), record.to_dict()


def _limits(start: float, database: Path, *, max_seconds: float,
            max_rss_mib: int, max_database_mib: int) -> None:
    if time.perf_counter() - start > max_seconds:
        raise TimeoutError("case exceeded --max-seconds")
    rss = _rss_bytes()
    if rss is not None and rss > max_rss_mib * 1024**2:
        raise MemoryError("case exceeded --max-rss-mib")
    db_bytes = _database_bytes(database)
    if db_bytes > max_database_mib * 1024**2:
        raise MemoryError("case exceeded --max-database-mib")


def run_case(count: int, *, seed: int, batch_size: int = 128,
             max_seconds: float = 180.0, max_rss_mib: int = 1024,
             max_database_mib: int = 2048, query_samples: int = 200) -> dict:
    if count < 1 or batch_size < 1 or query_samples < 1:
        raise ValueError("count, batch size and query samples must be positive")
    started = time.perf_counter()
    result = {"sources": count, "seed": seed, "batch_size": batch_size,
              "status": "failed", "failure": None, "generated": 0, "loaded": 0,
              "peak_backlog_sources": 0, "failed_operations": 0,
              "limits": {"seconds": max_seconds, "rss_mib": max_rss_mib,
                         "database_mib": max_database_mib}}
    rng = random.Random(seed)
    generation_ms: list[float] = []
    load_ms: list[float] = []
    key_ms: list[float] = []
    query_ms: list[float] = []
    tracemalloc.start()
    with tempfile.TemporaryDirectory(prefix="sylanne-source-bench-") as directory:
        database = Path(directory) / "sylanne3.sqlite3"
        discovered = discover_domain_registry(active_affect_scheme=_load_active_scheme(
            ROOT / "resources/catalogue/d04-affect-scheme.json"))
        if not discovered.complete:
            raise RuntimeError(f"incomplete active domain registry: {discovered.unavailable}")
        registry = discovered.type_registry
        result["live_catalogue_hash"] = registry.catalogue_hash
        result["live_catalogue_type_count"] = len(registry.specs)
        store = None
        try:
            open_start = time.perf_counter()
            store = GraphStore(database, registry)
            result["schema_open_ms"] = (time.perf_counter() - open_start) * 1000
            scope = Scope("benchmark-bot", "benchmark-persona", "benchmark-session")
            for offset in range(0, count, batch_size):
                size = min(batch_size, count - offset)
                tick = time.perf_counter()
                generated = [_source(seed, index, rng) for index in range(offset, offset + size)]
                generation_ms.append((time.perf_counter() - tick) * 1000 / size)
                result["generated"] += size
                result["peak_backlog_sources"] = max(
                    result["peak_backlog_sources"], result["generated"] - result["loaded"])
                writes = tuple(GraphWrite(key, value) for key, value in generated)
                event = Event(scope, f"batch-{offset:08d}", float(offset),
                              "synthetic-benchmark", {"count": size})
                tick = time.perf_counter()
                reads = tuple(GraphVersion(key, 0) for key, _ in generated)
                store.graph_commit(GraphCandidate(event, reads, writes))
                load_ms.append((time.perf_counter() - tick) * 1000 / size)
                result["loaded"] += size
                del generated, writes
                _limits(started, database, max_seconds=max_seconds,
                        max_rss_mib=max_rss_mib, max_database_mib=max_database_mib)
            # Timings include the real GraphStore key lookup and indexed paged query.
            samples = min(query_samples, count)
            for sample in range(samples):
                index = (sample * count) // samples
                key = source_key("benchmark-bot", "benchmark-persona",
                                 f"bench-{seed:08x}-{index:08d}")
                tick = time.perf_counter()
                snapshot = store.graph_snapshot((key,))
                key_ms.append((time.perf_counter() - tick) * 1000)
                if snapshot.get(key) is None:
                    raise AssertionError(f"missing committed source {index}")
                tick = time.perf_counter()
                page = store.graph_query("benchmark-bot", "benchmark-persona",
                                         type_names=("memory.source",), limit=100,
                                         after=key)
                query_ms.append((time.perf_counter() - tick) * 1000)
                if len(page.snapshot.atoms) > 100:
                    raise AssertionError("graph query exceeded page bound")
            connection = sqlite3.connect(database)
            try:
                plan = connection.execute(
                    "EXPLAIN QUERY PLAN SELECT token FROM graph_atoms "
                    "WHERE bot=? AND persona=? AND type_name=? AND token>? "
                    "ORDER BY token LIMIT 100",
                    ("benchmark-bot", "benchmark-persona", "memory.source", ""),
                ).fetchall()
                result["indexed_query_plan"] = [row[3] for row in plan]
                result["sqlite_page_count"] = connection.execute("PRAGMA page_count").fetchone()[0]
                result["sqlite_page_size"] = connection.execute("PRAGMA page_size").fetchone()[0]
            finally:
                connection.close()
            result["status"] = "completed"
        except (Exception, KeyboardInterrupt) as exc:
            result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            result["failed_operations"] = 1
        finally:
            result["database_bytes_at_stop"] = _database_bytes(database)
            if store is not None:
                store.close()
            _, peak_python = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            result["duration_seconds"] = time.perf_counter() - started
            result["peak_python_allocated_bytes"] = peak_python
            result["peak_rss_bytes"] = _rss_bytes()
            result["generation_batch_mean_per_source"] = _percentiles(generation_ms)
            result["load_batch_mean_per_source"] = _percentiles(load_ms)
            result["key_lookup"] = _percentiles(key_ms)
            result["indexed_page_query"] = _percentiles(query_ms)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="run 1k, 10k and 100k ladder")
    parser.add_argument("--smoke-count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=20260928)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--max-seconds", type=float, default=180.0)
    parser.add_argument("--max-rss-mib", type=int, default=1024)
    parser.add_argument("--max-database-mib", type=int, default=2048)
    parser.add_argument("--output", type=Path, help="JSON report path outside tracked runtime data")
    args = parser.parse_args(argv)
    if min(args.smoke_count, args.batch_size, args.max_seconds,
           args.max_rss_mib, args.max_database_mib) <= 0:
        parser.error("counts and ceilings must be positive")
    report = {"schema": "sylanne.synthetic-source-benchmark.v1",
              "classification": "synthetic GraphStore microbenchmark; not OPS-08 product acceptance",
              "python": sys.version, "platform": platform.platform(),
              "python_executable": sys.executable, "sqlite_version": sqlite3.sqlite_version,
              "processor": platform.processor(), "machine": platform.machine(),
              "logical_cpu_count": os.cpu_count(), "physical_memory_bytes": _physical_memory_bytes(),
              "source_identity": _source_identity(),
              "cases": []}
    counts = [1000, 10000, 100000] if args.full else [args.smoke_count]
    for count in counts:
        case = run_case(count, seed=args.seed, batch_size=args.batch_size,
                        max_seconds=args.max_seconds, max_rss_mib=args.max_rss_mib,
                        max_database_mib=args.max_database_mib)
        report["cases"].append(case)
        if case["status"] != "completed":
            break
    report["source_identity_after"] = _source_identity()
    report["source_unchanged_during_run"] = (
        report["source_identity"] == report["source_identity_after"])
    report["usable_for_same_source_comparison"] = (
        report["source_unchanged_during_run"]
        and all(case["status"] == "completed" for case in report["cases"]))
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)
    return 0 if report["usable_for_same_source_comparison"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
