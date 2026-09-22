# Embodiment 3.0 — foundation milestone contract

Status: approved architectural direction, first engineering slice. This is a new implementation with no legacy execution dependencies. Full product acceptance remains future work.

## Shared Python interfaces (`sylanne3.contracts`)
All public records are frozen dataclasses. JSON payloads must be finite, serializable data; stores detach mutable containers at read/write boundaries. Scope identity is the exact `(bot, persona, session)` triple, all nonempty strings. No unscoped fallback.

```python
Scope(bot: str, persona: str, session: str)
AtomVersion(name: str, revision: int)  # revision 0 means absent
Atom(name: str, revision: int, value: dict)
Snapshot(scope: Scope, atoms: tuple[Atom, ...])
# Snapshot.get(name) -> Atom | None; Snapshot.versions -> tuple[AtomVersion,...]
# Absent requested names must appear as revision-zero atoms (value={}) so versions include absence.
Event(scope: Scope, event_id: str, occurred_at: float, kind: str, payload: dict)
# Event.digest is SHA256 of canonical JSON of ALL fields; event_id is nonempty.
Write(name: str, value: dict)
Candidate(event: Event, reads: tuple[AtomVersion, ...], writes: tuple[Write, ...])
CommitReceipt(status: str, revisions: tuple[AtomVersion, ...])
# status is "committed" or "duplicate".
StepResult(done: bool, value: object = None)
```

`Store(path)` uses SQLite and owns all schema creation. `snapshot(scope, names)` returns a detached snapshot for every requested name. `commit(candidate)` checks the complete read set (including absence), requires each write name in the read set, validates duplicate names and finite JSON, and records the event and all writes in one transaction. Replaying an identical event returns duplicate without changing state, even if old reads are now stale. Reusing the event ID with different content raises `EventConflict`. Version mismatch raises `StaleRead`; neither failure leaves partial writes/events. `close()` closes resources. All scopes are isolated in every SQL key. Store methods are synchronous and thread-safe; runtime must offload them.

`BoundedScheduler(workers=2, capacity=32, quantum=4)` exposes `async run(scope: Scope, job) -> object` and `async close()`. A job implements synchronous `step(budget: int, cancelled: threading.Event) -> StepResult`. Admission is bounded over queued AND running jobs; overflow raises `CapacityExceeded` immediately. At most one step of a job runs at once. Pending jobs receive fair service across scopes; repeated refinement yields its worker. Cancelling a caller signals the job, removes pending work, and running work retains its capacity until it actually exits. close cancels pending work and joins owned workers without blocking the event loop. No coroutine/thread per atom.

## Native kernel and binding (`native/`, `sylanne3.native`)
Rust std-only crate `sylanne3_kernel`, cdylib + rlib. No legacy code. First slice bounds `1 <= n <= 256`; finite arrays; masses and local recovery strictly positive; edges symmetric, nonnegative and zero-diagonal; dt positive. M is diagonal. K = diag(recovery) + graph Laplacian(edges). This ensures full coverage and a positive lower spectral bound.

One immutable solve problem: A = M + dt*K, b = M*previous + dt*drive. drive is a constant input over the fixed interval dt, not an impulse or a repeated per-sweep dose. Repeated precision work always uses this same A,b and advances only the numerical iterate. The first implementation uses bounded Gauss-Seidel sweeps and scans the FULL residual. In exact arithmetic the error bound is `||A*x-b||2 / min_i(mass_i + dt*recovery_i)`. The implemented certificate must include its documented floating-point roundoff allowance and conservative lower bound; it must reject parameter scales for which the recovery term or certificate cannot be represented reliably. Residual evaluation preserves the base-plus-edge-differences structure instead of allowing large cancelling matrix entries to erase recovery. This bounds the discrete-system error within the implemented numerical contract only, not time-integration accuracy or an interval-arithmetic proof.

ABI (C calling convention):
```c
uint32_t sylanne3_abi_version(void); // 1
int32_t sylanne3_refine(size_t n,
  const double *mass, const double *recovery, const double *edges, // edges row-major n*n
  const double *previous, const double *drive, double dt,
  const double *initial, size_t max_sweeps, double tolerance,
  double *solution, double *metrics); // metrics[4]
```
Return 0 converged, 1 needs refinement, negative invalid input/computation failure. metrics: residual_l2, error_bound, energy_delta (0.5*x'Mx minus initial physical state's energy), sweeps_used. Exact array lengths are established by the Python binding; Rust rejects null pointers, invalid scalars and unsupported sizes before computation. Rust unsafe pointer contract must be documented. Stop on nonfinite intermediate values; do not return a false certificate. No worker-spawning or I/O inside kernel.

Python `NativeKernel(library_path=None)` discovers the platform release/debug library under rewrite/native/target (or an explicit path); absence/version mismatch is an explicit error, never an implicit Python fallback. `kernel.job(*, mass, recovery, edges, previous, drive, dt, tolerance=1e-8, max_total_sweeps=10000)` returns a resumable SolveJob using copied immutable input. It implements StepResult and checks cancellation before/after a bounded native quantum. Completed value is `SolveResult(solution: tuple[float,...], residual_l2: float, error_bound: float, energy_delta: float, sweeps: int)`. Exhaustion raises `AccuracyNotMet`; cancelled work cannot be accepted. Offline independent reference solves belong in tests, not runtime fallback.

## New end-to-end engine (`sylanne3.engine`)
`Engine(store, scheduler, kernel, transport)` and `async handle(event) -> TurnResult` demonstrate one-persona/session inbound, correction, refinement, atomic state/action creation, and delivery settlement. `transport.send(contract)` is an async protocol. `RecordingTransport` is an explicitly local test/demo sink, not a real platform.

First slice accepts typed semantic event payloads (not free-form LLM inference). Evidence events carry complete propositions and scoped subjects. Correction references an earlier interpretation ID; it invalidates that interpretation and updates the derived reaction, not the original observed text or already-delivered history. Recompute reaction from valid interpretation evidence with original timestamps; correction is not repeated application of the original load, and must not reset physical time or unrelated personality. If adequate replay cannot be established, return an explicit unsupported/conflict result rather than invent an inverse.

The first semantic fixture may support only bounded `interpretation` and `correction` kinds with a single global reaction solve for that scope. Record this restriction; do not pretend arbitrary semantic parsing or local sparse truncation is implemented. Engine chooses and documents exact payload shapes in README/tests. Numerical state, interpretation validity, and a typed ActionContract must share a committed dependency chain. State-dependent deterministic expression is acceptable for this slice and must have a counterfactual test (changing relevant certified state changes behavior; unrelated fields do not).

Delivery is a separately observed external effect. Commit a pending outbox/action before send, dispatch only a freshly claimed matching action, then record `delivered`, `failed`, or `unknown`. Cancel/interrupt after external acceptance may be unknown; never automatically replay an unknown non-idempotent send. Repeated event IDs must not send twice. An already-delivered message remains in history after correction. Do not claim generic exactly-once external delivery. A crash between action commit and send/result must remain diagnosable via outbox state. Model/core suggestions alone must not create a delivered receipt.

## Verification and milestone boundary
Meaningful tests must first fail on missing behavior, then pass. Numerical comparison includes coupled exact solution, independent dense solve, no-input energy decay, budget partition invariance, invalid parameter rejection, global residual. Runtime comparison includes restart, stale reads, multi-write rollback, duplicate/reused event IDs, scope isolation, bounded admission, fair service, actual worker cancellation/close. Integration covers correction, state-derived action, stale/duplicate suppression and delivery unknown/failure.

This milestone does not ship a 3.0 release, switch the installed 2.5 entry point, provide a new UI, claim calibrated emotion semantics, claim sublinear sparse solve, or establish actual AstrBot/QQ behavior. Subsequent phases replace the remaining product before packaging. Root legacy files are reference assets only; import checks enforce the new execution boundary.
