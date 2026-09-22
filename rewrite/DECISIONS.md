# Foundation decisions and deferred claims

## 1. Separate production entry from the new engineering slice

The approved target is a whole-plugin rewrite. The development slice is rooted in `rewrite/`; keeping the 2.5.1 entry point in this checkout is temporary reference preservation, not reuse by the new runtime. The new import graph may not enter old `sylanne_alpha`, `v2core`, `_engine`, or `v3core`. Publishing or changing an installed plugin is outside this initial milestone.

## 2. Native C ABI for the first kernel

Rust performs numerical work; Python owns host-facing orchestration. Use a small versioned C ABI via standard-library ctypes for this first slice, instead of adding a Python-extension build dependency before the compute contract is tested. Arrays are copied and length-checked by the binding. Rust does not retain their addresses beyond a call. Native calls run inside a bounded executor, never on the event-loop thread. Releasing the GIL alone does not free that thread. See the official [ctypes documentation](https://docs.python.org/3.13/library/ctypes.html) and [asyncio development notes](https://docs.python.org/3.13/library/asyncio-dev.html).

Cross-platform packaged binaries and release ABI compatibility remain later acceptance gates. A missing native library raises explicitly; no silent Python runtime fallback disguises a missing native implementation.

## 3. Restricted constructive operator family

For the initial kernel, M is positive diagonal, every local recovery coefficient is strictly positive, and allowed couplings are nonnegative symmetric graph weights. K is the local recovery diagonal plus the graph Laplacian. Every state is covered; strict recovery and the discrete lower bound are inspectable. This does not identify psychological axes or calibrate any emotion model.

The reference equation is A*x=b with A=M+h*K and b=M*x0+h*drive. Inputs represent a constant load over a fixed, explicit interval. Numerical sweeps do not change that interval, repeat the event, or modify x0. Gauss-Seidel is a first bounded solver, not a commitment that it will outperform a direct solve on small blocks.

## 4. Full certificate before local truncation

The first solver always computes the complete residual of the small coupled system. The exact-arithmetic error bound uses min_i(M_i+h*recovery_i); the implemented bound adds a documented roundoff allowance and rejects ill-scaled inputs. Requested tolerance is on the discrete state error, not a claim about time-discretization accuracy, calibrated semantics, or natural-language quality. The computed floating-point residual is an engineering certificate; it is not an interval-arithmetic proof against arbitrary roundoff/conditioning.

Independent review reproduced a false-zero residual when coupling 1e20 erased a recovery diagonal of 2. This must be regression-tested and rejected or correctly solved. A disclaimer alone is not a fix; representability and parameter-domain checks belong in the algorithm.

Sparse active-set expansion and asynchronous local boundary solves are deferred until their inactive-state residual bookkeeping can be independently compared to full recomputation. No work reduction is claimed for the current dense scan.

## 5. Typed temporal episodes in the first engine

An interpretation describes a scoped observed episode with a proposition, a bounded two-component drive, and an explicit start/end interval. The end is the event timestamp. These are fixture semantics for demonstrating the execution contract, not automatic emotion extraction from chat text. Corrections invalidate interpretations, retain original observations/endpoints and already-delivered actions, and replay the fixed chronological partition to current time. Fixed unit mass gives nonexpansive homogeneous propagation; per-interval solver error budgets compose into a total bound.

The two-component fixture does not freeze the dimensionality of the final character model. Long-term personality learning, relationship semantics, and probabilistic language proposals remain separate implementation phases.

## 6. Atomic authority and external delivery

The SQLite transaction validates all read versions, including absence, before applying all candidate changes and recording the event. Same event ID plus same canonical content is idempotent; different content is a conflict. Actions are created from the committed numerical state/evidence and stored as pending outbox records. Sending and observing its result are separate lifecycle events.

An unknown external result cannot be silently retried on a non-idempotent transport. A delivery receipt requires transport evidence; a generated action is not a sent message. Correction never edits the record of a message already sent. The first recording transport proves local sequencing only; AstrBot and messaging-platform behavior are not accepted by these tests.

## 7. Routing and audit evidence

DevKit workspace registration succeeded. Initial targeted snapshot: `sha256:e7292d568c096da01273e69ab485dd7f6fd9109d3f1d876c346b17855f1e9874`, state `INDEX_PARTIAL` (4 files, 1321 gaps). No strict-index/compiled-route acceptance is claimed. Implementation is coordinated directly under the user's explicit delegation instruction, with disjoint named write scopes and main-agent integration/review. Initial workers used Astra medium for code/design and Luna low for mechanical environment/tooling work. The user subsequently requested lower-cost coding: further routine implementation goes to Sol, mechanical work to Luna, and Astra is reserved primarily for architecture, numerical reasoning and critical review. Existing in-flight cancellation repair is allowed to finish without new coding scope.

## 8. Remaining whole-product work

- Real AstrBot lifecycle and Provider adaptation, platform delivery, timeout/interrupt recovery.
- Model-backed typed semantic proposals and independently evaluated expression consistency.
- Larger atom graph, incremental invalidation, local/full solver comparisons and scaling measurements.
- Durable persona/relationship model revisions and provenance-based migration from 2.5.1.
- Memory indexing/forgetting, sparse life events, topic/intent/commitment scheduling.
- New role workbench, presets, diagnostics, distribution and native wheels/binaries.
- Longitudinal behavioral/cost comparisons and formal 3.0 release acceptance.

## 9. Host integration before calibrated behavior

Phase 5a originally proposed a separate developer entry point. The user subsequently required old interfaces and core to retire, so the new root entry is now authoritative and no parallel old runtime is retained. It remains disabled by default and exposes an explicit development command while the full heavyweight system is implemented. This is an implementation sequence, not a reduction in the approved product scope.

The model receives bounded text and proposes only a finite appraisal plus verbatim evidence. The application owns identifiers, subject, interval, drive construction and action rendering. One durable claim precedes the provider call; restart duplicates and owner-changing replays cannot invoke it again. The claim's intake scope and the resulting state's persona/conversation scope are distinct on purpose.

The current two-vector mapping and fixed expression templates exercise that authority chain. They are not the final ontology, and their narrow form must not become an accidental product constraint. Next work must expand semantically owned operators, long-term personality/relationship parameters, evidence corrections and memory using the same state/action contract, with empirical evaluation separate from numeric certificates.

The adapter is checked against an isolated AstrBot 4.28.1 distribution. SDK execution with controlled provider and platform inputs is a separate acceptance level from the full plugin manager, connected model providers, messaging-platform delivery and complete 3.0 release readiness.
