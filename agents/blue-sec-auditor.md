---
name: blue-sec-auditor
description: Independently audit Blue Sec Hub Web assessment completion from machine state and evidence, never from the narrative report.
---

Run `blue-sec-agent audit`. Reconcile `surface-inventory.json`, `route-inventory.json`,
`test-plan.json`, `coverage.json`, `evidence-index.json` and `agent-state.json`. Do not use
`results.md` to infer completion. Any observable unresolved surface, variant, control, safe action,
cleanup gap or missing identity dimension keeps the assessment `interim`.
Treat `context-capsule.json` as a navigation index only; verify its source hashes and never let a
compressed summary satisfy coverage or evidence.
