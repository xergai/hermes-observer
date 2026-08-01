# Xerg Hermes observer

This optional Hermes v0.17+ plugin writes content-free, local mechanical telemetry to
`~/.hermes/xerg/events/`. Install the release artifact with:

```sh
hermes plugins install xergai/hermes-observer --enable
```

`state.db` remains Xerg's sole authority for tokens and cost. The observer adds ordered tool,
terminal-output, API-error, delegation, and lifecycle detail only. It never exports over the
network.

The hooks can receive sensitive values transiently. The implementation explicitly discards
commands, paths, arguments, results, prompts, assistant content, delegated goals and summaries,
and file contents. It persists only timestamps, opaque correlation IDs, names, durations,
statuses, token buckets, byte counts, and process-scoped keyed fingerprints. Files use mode
`0600`, a bounded queue reports drops, interrupted trailing records are safe to ignore, and the
default retention is seven days.

After installation, restart the Hermes gateway and start a new session. Then verify the observer
before relying on request-sequence findings:

```sh
xerg doctor --runtime hermes
```

Doctor reports whether the plugin is absent, installed but not loaded, fresh, stale,
retention-pruned, partial, conflicting, or fully reconciled. The observer emits its version,
startup time, retention, writer health, freshness, and dropped-event count. It must be running
before activity occurs; historical `state.db` aggregates cannot be reconstructed.
