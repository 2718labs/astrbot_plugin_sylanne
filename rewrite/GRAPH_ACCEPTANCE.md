# Typed graph and recall-control acceptance

Date: 2026-09-22. Branch: `codex/embodiment-3-rewrite`; uncommitted implementation.

## Verified source and commands

Core/native receipt: `artifacts/verification-20260922T105425.979105Z.json` and matching `.log`.
SDK receipt: `artifacts/host-verification-20260922T105426.385408Z.json` and matching `.log`.
Both receipts report `source_drift=false`; a subsequent comparison of every recorded SHA256 against the current checkout found zero mismatches.

Executed from repository root:

```powershell
& 'C:\Users\pidan\AppData\Roaming\uv\python\cpython-3.13.14-windows-x86_64-none\python.exe' rewrite/tools/verify.py
& 'D:\bun\tmp\codex\sylanne3-host\Scripts\python.exe' rewrite/tools/verify_host.py
```

- 122 core Python tests passed.
- 2 Rust tests passed; Cargo format/check/test/release build passed.
- 9 controlled SDK tests passed with AstrBot 4.28.1.
- Python compilation and retired-import boundary checks passed.
- Ruff 0.16.0 from an existing local uv cache passed; `git diff --check` passed. The initial uv tool resolver could not reach PyPI due to TLS EOF; the actual local Ruff executable was used, without changing TLS policy or installing another dependency.

## What the evidence covers

- Typed persona/relation/scene/event/activity owners, canonical keys and frozen type catalog checks.
- Coherent SQLite snapshots, cross-owner commits within one bot/persona namespace, complete read CAS, namespace epochs for newly appearing evidence, event-content deduplication and conflicting event rejection.
- Immutable source protection, dependency revision history and event-linked read receipts.
- Reverse dependency invalidation through freshly recomputed intermediate nodes; unrelated owners stay unchanged. Missing-key dependencies observe absence and invalidate when the key appears. Invalid existing dependencies are rejected.
- Iterative cycle rejection, deterministic pure DAG ordering, sparse/full arithmetic recomputation agreement, delayed frozen reads, detached values and resumable worker jobs.
- Bounded runtime admission, off-event-loop computation/SQLite, stale-result rejection, cancellation ownership, shared-resource lifecycle and truthful cancellation during commit.
- Deterministic recall triggers, mandatory checks, working-set activation, bounded search stages, independently measured monotonic timeout, atomic result acceptance, source-family deduplication, same-source coverage merging and at most two reserved auxiliary model calls.

Cross-domain scenarios in `tests/test_graph_causality.py` prove that a corrected interpretation invalidates current relationship/narrative views while retaining actual source history; recomputing only the relationship does not silently keep the old summary valid; new evidence expires a query even when previously read atoms did not change.

## Remaining product requirements

This is phase 5b infrastructure and recall control, not complete memory or Sylanne 3.0 acceptance.

- Root AstrBot/application still uses the explicitly labelled two-component semantic fixture. The typed graph runtime and recall controller are not yet integrated into that production entry.
- Pure operator DAGs are executable. Registered coupled SCC solvers, general temporal orchestration, versioned operator-package replay and large-graph numerical local truncation remain unimplemented.
- The graph store is a trusted in-process API. It enforces namespace/type constraints, not the complete domain writer-capability and audience/purpose policy required by the product.
- Memory source/evidence schemas, event segmentation, indexed retrieval, temporal/audience filtering, source deletion, durable recall/cooldown and all domain learning semantics remain to be integrated.
- Recall `Evidence` is supplied by a trusted caller; this controller does not prove source truth, independent acquisition, validity, permissions or actual model-call billing. Its recall-experience output is a candidate, not a committed experience.
- Graph cycle checks currently inspect the namespace graph. No 1k/10k/100k memory performance or throughput claim has been measured.
- Full character domains, workbench, migration, native distribution, actual platform/provider delivery, Linux/remote CI and longitudinal quality/cost gates remain open in `REQUIREMENTS.md`.

Manual/live acceptance later requires a fresh AstrBot test instance, configured provider and a designated test conversation. Check persona/session changes, private/group audience isolation, real delivery/unknown outcomes, restart and unload using the future product runtime. Current controlled SDK tests cannot substitute for those checks.
