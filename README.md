# Xerg Hermes observer

Artifact version 0.35.3 preserves the observer behavior and compatibility evidence below.

This optional plugin writes content-free, local mechanical telemetry to the
selected Hermes home's `xerg/events/`. The 0.34.1 compatibility update passed
bounded live request-detail, accounting-reconciliation, privacy, and baseline
selection acceptance on these exact Hermes pins:

- v0.20.1: `f80f453ae0679347e38abc917c7f94f717bf96c5`
- v0.20.6: `5fc308a70719a83cccdbba4c0e39c23f5a8239d5`
- v0.21.0: `29112bef099274229cadff79cdff7bf7b99c4b77`

This acceptance covers the exercised workloads and the limitations below, not
complete delivery in every concurrent workload. The separately pinned third-party
OTLP integration has its own acceptance and is not required by this observer.
The install command selects the currently published observer artifact. Verify its
version before relying on the 0.34.1 capabilities:

```sh
hermes plugins install xergai/hermes-observer --enable
```

**Dispatcher compatibility adjustment:** on pinned Hermes v0.20.6 and v0.21.0,
Xerg omits `pre_tool_call` registration because overlapping invocations can cause
the upstream policy dispatcher to block before Xerg's callback runs. Pinned v0.20.1
retains the demonstrated safe older hook. Unknown/unverified versions omit it
conservatively. No runtime safety setting or other plugin is disabled. Actual
zero-model dispatcher controls cover normal/concurrent behavior, independent
security blocks, profile isolation and unload/reload; they are not live certification.

Requested-versus-executed comparison is explicitly unavailable on those affected
runtimes. Delivered post-tool executed fingerprints, sizes, results and durations
remain local evidence, not invented requested arguments or execution-start order.
Pre-dependent repeated-input, sequential-burst and state-write metrics/deltas are
omitted, not zero. Ledger/health capability fields describe registration, not
guaranteed callback delivery. The additive `lifecycle_observation` field is
`complete-capable` on pinned v0.20.1, `partial` on pinned v0.20.6/v0.21.0, and
`unknown` on unverified versions. Local audit coverage exposes
`lifecycleObservation` and `upstreamSuppressionCountAvailable: false`. Upstream
may suppress overlapping post/API/lifecycle callbacks without incrementing Xerg's
writer-drop count; no upstream suppression count is inferred, including zero.
Missing API starts prevent exact reconciliation; authoritative economics remain
aggregate. State-only accounting remains available.

The 0.34.1 observer additively retains delivered numeric native
`started_at` and `ended_at` on API records in the same v1 ledger; missing/invalid
values stay absent. These are not the observer writer's timestamp. Equivalent
captured starts in one scoped logical request can reconcile to one completion
and one state-accounted request. Local `observedAttemptCount` counts delivered
native starts, not every provider attempt; latency includes the logical retry
interval, with no per-attempt timing or cost claim. Errors, conflicts, missing
native metadata and incomplete state reconciliation retain aggregate fallback.
Old captures are not repaired. The observer still adds no monetary record:
superseded truncated-response usage omitted by the tested Hermes state paths
cannot be reconstructed or assumed to have zero provider cost.

Timing and order require actual uniquely correlated starts and ends, not equal
counts or spawn timestamps. Missing queue time is omitted. Partial mechanical
totals are observed lower bounds, not exact before/after improvements or resolved
findings. Complete-capable v0.20.1 still requires evidence-level reconciliation;
the capability alone never certifies an audit. Original full-delivery diagnostics
remain separate from acceptance of these explicit compatibility limits.

The post-delegation hook retains a bounded, content-free local `subagent-result`
record with native status and an optional boolean `metadata.schemaValid`.
Hermes v0.20.1/v0.20.6 can report `completed` alongside `schema_valid: false`:
execution completion is not schema-valid success. Child output is discarded;
neither field declares a successful outcome, savings, or avoidable spend. Recorded
child cost and activity remain intact.

`state.db` remains Xerg's sole authority for tokens and cost. The observer adds observed tool,
terminal-output, API-error, delegation, and lifecycle detail only. It never exports over the
network.

Hermes v0.20.1 auxiliary model tasks such as `title_generation` do not pass through the public
per-request hooks used by this plugin. Xerg keeps those task-scoped charges as authoritative
aggregates with sequence coverage marked unavailable, while independently reconciling observable
main and delegated requests. The plugin does not patch Hermes private internals.

The hooks can receive sensitive values transiently. The implementation explicitly discards
commands, paths, arguments, results, prompts, assistant content, delegated goals and summaries,
and file contents. It persists only timestamps, opaque correlation IDs, names, durations,
statuses, token buckets, byte counts, and process-scoped keyed fingerprints. Files use mode
`0600`, a bounded queue reports drops, interrupted trailing records are safe to ignore, and the
default retention is seven days.

The observer keeps the `xerg.hermes.observer.v1` ledger and adds no heartbeat records to it.
Registration resolves Hermes's profile-aware home and eagerly creates a mode-`0600`, per-registration
`observer-health-<pid>-<random>.json` sidecar. The sidecar is atomically replaced every 60 seconds and
marked stopped on orderly shutdown; a missing heartbeat becomes stale after 150 seconds. Health
files are pruned separately and never enter evidence counts, coverage, retention windows,
economics, or audit identity. Each heartbeat touches the process JSONL only so older Xerg doctor
versions retain their ledger-freshness behavior.

Writers, keyed fingerprints, and correlation queues are isolated by registered
home, including two profiles in one process. `ctx.on_unload` closes that scope;
`atexit` remains a fallback. Reloads do not overwrite a prior process's files.
The ledger and health include an additive, path-free `profile_scope_id`. New Xerg
also reads old v1 ledgers/health filenames; unscoped evidence cannot join an
ambiguous all-profile audit.

Recognized `request_messages` (OpenAI messages, Anthropic tool-result blocks, or
Responses output items) are measured with basis `hermes-request-hook`. Tool-result
count/bytes describe that serialized hook representation, not exact HTTP bytes.
Raw post-tool returned bytes remain separate: transforms or spilling can change
what reaches the model. No spill file is inspected. Post-hook arguments supply
executed fingerprints when correlated; blocked/cancelled calls are not executions.
Callbacks return `None`, use bounded content/node/depth and queue limits, perform
no disk/network waits, and turn unsupported inputs or failures into reduced
coverage rather than blocking Hermes pre-tool execution.
An unsupported or oversized system/tool definition or post-tool argument/result
can drop the whole callback event, not just its size measurement. The local drop
is recorded; it is not upstream suppression or proof of complete coverage.
State-authoritative economics remain available through conservative fallback.

The observer ledger still supports the optional fields introduced in 0.24.1.
Hermes v0.17-v0.19 terminal captures remain exact. Hermes v0.20 bounds terminal output earlier;
when it provides `output_total_chars`, the observer records that character count as a conservative
UTF-8 byte floor and marks the measurement `lower-bound`. It falls back to Hermes's marker count
only when the structured field is unavailable. Returned bytes remain exact, and missing totals stay
unavailable rather than being guessed. The observer never reads, stats, resolves, or persists
`full_output_path`, even if a tool result contains a malicious path.

Xerg 0.24.0 was not certified for Hermes v0.20.x terminal mechanics and could understate generated
or truncated byte metrics. Use matching Xerg CLI and observer releases for the
0.34.1 compatibility behavior; confirm the published versions before upgrading.
The live observer preflight is available from 0.24.2. An older
Xerg accepts the v1 ledger and ignores the new optional lower-bound fields; a new Xerg accepts old
ledgers but omits generated/truncated findings when the measurement basis cannot be proven.

After installation, restart the Hermes gateway and start a new session. Then verify the observer
before relying on request-sequence findings:

```sh
xerg doctor --runtime hermes --require-observer-live
```

Doctor reports operational liveness separately from audit-window reconciliation. The strict
preflight exits `5` unless a current process is running and its writer is not known unhealthy.
Observer health is a continuous production-coverage concern, not merely a test prerequisite. It
must be running before sequence-dependent activity occurs; historical `state.db` aggregates cannot
be reconstructed. Existing aggregate-economics audits remain available with a prominent
aggregate-only warning.

Maintainer acceptance commands and their exact runtime pins are documented in
[`scripts/acceptance/hermes-compatibility.md`](../../scripts/acceptance/hermes-compatibility.md).
The no-cost real-dispatcher test uses synthetic payloads; it does not certify live
Bot/gateway/delegation behavior or replace credentialed economic acceptance.
