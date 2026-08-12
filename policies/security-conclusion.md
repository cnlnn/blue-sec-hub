<!-- blue-sec-global-security-conclusion-policy -->

## Mandatory Security Conclusion Contract

- Classify every security claim as a historical claim, risk signal, static capability, incident observation, or current vulnerability. Do not merge those evidence classes.
- An incomplete attack chain is a candidate, not a confirmed vulnerability. It may state investigation priority and potential impact, but must not assign formal severity, CVSS, confirmed impact, or a confirmed-vulnerability title.
- Confirm a current vulnerability only when direct evidence closes the attacker source, controlled input, reachable path, consumer or sink, trigger result, and observable impact. A code-execution claim also requires a proven privilege bridge to the operating-system effect.
- Static code, dangerous configuration, a sink, IPC handler, upload success, or a version match confirms only that node. It does not confirm the full exploit chain.
- Preserve a high-impact static node as a `static-capability` or `risk-signal` with a candidate validation queue. Do not discard it as `not-a-finding` until intended-safe behavior or an evidence-backed rejection closes the relevant paths.
- Every high-impact candidate must create and continue a prerequisite-validation queue. A high-risk signal, scanner alert, or first confirmed finding is never a completion condition.
- Missing credentials, environment, authorization, or another external prerequisite is `blocked-external`; preserve the resume condition and keep the task `interim`.
- A confirmed high-severity finding may be reported immediately, but continue the remaining scope, adjacent attack surface, unresolved candidates, cleanup, and evidence audit unless the user narrows scope or safety requires pausing.
- Historical reports retain their reported wording only as `historical-claim`; observed command execution in DFIR is an `incident-observation` unless root-cause evidence proves the vulnerability.
- Label every prerequisite with its provenance. In a black-box assessment, only `attacker-public`, `attacker-authenticated`, and `attacker-derived` evidence may close an attacker prerequisite.
- Treat `tester-provided`, `historical-report`, `internal-log`, and `source-code` values as investigation seeds unless the declared attacker model independently grants that access. Continue searching for an attacker-reachable producer.
- A null or error response for a random, stale, or unknown-ownership object cannot prove remediation, authorization, or non-exploitability. Retest with a current valid object and a matched control.
- When using traffic history, record the time range, source coverage, parser failures, and the latest successful authentication plus later accepted requests. One malformed record or failed parse cannot establish that no valid session exists.
- Keep finding state and task state separate: an unresolved finding uses `validation_state=candidate`; if assessment coverage, queues, or blockers remain, the task-level `conclusion_state=interim`, never `complete`.
- A high-impact static node with an untested prerequisite is still a candidate requiring investigation. Use `not-a-finding` only after intended-safe behavior or an evidence-backed rejection closes that path.
