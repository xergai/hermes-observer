# Xerg Hermes observer

This optional Hermes v0.17-v0.20.1 plugin writes content-free, local mechanical telemetry to
`~/.hermes/xerg/events/`. Install the release artifact with:

```sh
hermes plugins install xergai/hermes-observer --enable
```

`state.db` remains Xerg's sole authority for tokens and cost. The observer adds ordered tool,
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

The 0.31.0 observer keeps the `xerg.hermes.observer.v1` ledger and adds no heartbeat records to it.
Instead, registration eagerly creates a mode-`0600`, per-process
`observer-health-<pid>.json` sidecar. The sidecar is atomically replaced every 60 seconds and
marked stopped on orderly shutdown; a missing heartbeat becomes stale after 150 seconds. Health
files are pruned separately and never enter evidence counts, coverage, retention windows,
economics, or audit identity. Each heartbeat touches the process JSONL only so older Xerg doctor
versions retain their ledger-freshness behavior.

The observer ledger still supports the optional fields introduced in 0.24.1.
Hermes v0.17-v0.19 terminal captures remain exact. Hermes v0.20 bounds terminal output earlier;
when it provides `output_total_chars`, the observer records that character count as a conservative
UTF-8 byte floor and marks the measurement `lower-bound`. It falls back to Hermes's marker count
only when the structured field is unavailable. Returned bytes remain exact, and missing totals stay
unavailable rather than being guessed. The observer never reads, stats, resolves, or persists
`full_output_path`, even if a tool result contains a malicious path.

Xerg 0.24.0 was not certified for Hermes v0.20.x terminal mechanics and could understate generated
or truncated byte metrics. Install Xerg and this observer at 0.31.0 for v0.20.x support and live
observer preflight. An older
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
