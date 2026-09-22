# Engine first vertical slice

This is a bounded, uncalibrated semantic fixture, not natural-language interpretation or a deployed personality system. The only modeled state is a two-component reaction per exact `(bot, persona, session)` scope. No real messages are sent by `RecordingTransport` or the demo.

## Typed inputs

`Event(scope, event_id, occurred_at, "interpretation", payload)`:

```json
{"interpretation_id":"evidence-1","subject":{"bot":"b","persona":"p","session":"s"},"proposition":"A complete typed proposition","drive":[6.0,0.0],"start_at":0.0}
```

The event represents an already-observed episode with a constant drive over `[start_at, occurred_at]`; it is not an instantaneous chat impulse. Require `0 <= start_at < occurred_at`, two finite drive components bounded by 1000 in absolute value, a nonempty proposition, a new interpretation ID, and exact matching subject scope. Maximum 256 interpretations per scope. `occurred_at` is an abstract physical time coordinate starting at zero and never decreases across events; it need not be a Unix timestamp.

A correction has kind `correction` and exactly `{"target_interpretation_id":"evidence-1"}`. It invalidates one still-valid interpretation in the same scope. Missing targets, repeated invalidations, backwards time and unsupported shapes explicitly fail. Observed propositions and old action/delivery records are retained. Repeated identical event IDs return duplicate without sending; changed content conflicts. Internal delivery event IDs use reserved prefix `__delivery__:`.

## Causal replay and certified decisions

Every accepted event replays from zero state at time zero. The interval partition retains all observed episode endpoints and prior correction timestamps, including endpoints of invalidated evidence. In each interval, only valid overlapping episodes contribute summed constant drive. Zero-input gaps recover normally. Correction is neither a negative dose nor another dose of the original event. Full replay is intentionally bounded by this fixture's small evidence capacity; no sparse or sublinear performance claim is made.

Fixed parameters are mass `(1,1)`, recovery `(1,1)`, and symmetric cross-edge `0.25`. Each backward-Euler interval is solved through a real resumable native job in `BoundedScheduler`. A total error budget of `1e-8` is divided among intervals. Because unit-mass homogeneous propagation with fixed SPD K is L2 non-expansive, the sum of local native error bounds bounds deviation from the exact discrete replay trajectory. This does not certify continuous-time integration accuracy, even for long intervals.

Expression reads only component zero and the accumulated error bound. Entire certified interval above `0.5` means `engage`; below `-0.5` means `withdraw`; wholly inside the middle band means `neutral`; otherwise `uncertain`. These names and thresholds are deterministic fixture semantics, not validated emotions. Tests vary relevant drives and unrelated proposition wording to verify the readout dependency.

## Atomicity and delivery

`Engine.prepare(event)` reads all four atoms `reaction`, `interpretations`, `actions`, `outbox`, performs native work, and atomically commits their updates with the original event. Every atom revision, including absent atoms, is part of the candidate read set. A changed dependency returns `TurnResult(status="stale")`; no action is sent. `Engine.handle(event)` prepares and then separately dispatches a newly committed action. Action IDs derive from the complete scoped event digest.

A pending action records its exact reaction and interpretation revisions. Claim reads the full dependency set and atomically changes pending to sending. A newer reaction or interpretation supersedes a pending action before claim. Once claimed, a send cannot be recalled by correction. The action remains tied to its historical certified state. Already-delivered records remain delivered; no compensating external send is automatically inferred.

Transport return means delivered in that adapter's contract; `DeliveryFailed` is reserved for definite nonacceptance. Other exceptions and cancellation during sending produce unknown. Unknown/failed/sending actions are never automatically resent. The recording sink's delivered status means local sink acceptance only. Claim and receipt persistence are shielded and joined even under repeated cancellation. If cancellation arrives during claim and the claim commits, dispatch records `failed` with `cancelled_before_send` and never calls transport. Cancellation during `prepare` may leave an atomically committed pending action; replay reports duplicate and does not automatically send that pending record. A process crash can leave pending or sending records for inspection, and no generic exactly-once external guarantee is claimed. There is no automatic restart recovery dispatcher in this slice.

All engine SQLite calls run via `asyncio.to_thread`. Python semantic replay orchestration is bounded; numerical refinement runs through the owned scheduler. No legacy imports, platform adapters, free-form LLM parser, automatic UI integration, or generic personality updates are implemented.

Run from `rewrite` with the compiled native library available: `python -m sylanne3.demo`.
