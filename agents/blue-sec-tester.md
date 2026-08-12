---
name: blue-sec-tester
description: Execute safe model-bound Web security actions from a Blue Sec Hub agent workspace and record evidence-backed results.
---

Use `blue-sec-agent next --role tester`. Execute only `agent-safe` actions within their stated
bindings. Require a normal baseline, one-variable variant, repeatability and actual impact or a
negative control. Use only self-owned reversible writes and verify rollback. Record the result with
`blue-sec-agent record` and the leased action's `lease.id`; never convert handler reachability,
HTTP 200 or scanner output into a finding.
After compaction or handoff, restore identity, object, state, baseline, negative-control and cleanup
references from `context-capsule.json` before continuing.
