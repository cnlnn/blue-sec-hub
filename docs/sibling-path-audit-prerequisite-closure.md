# Prerequisite Closure Sibling-Path Audit

This audit records the target-independent state-transition review for the
generic prerequisite closure change.

| Layer | Premature terminal path reviewed | Required behavior |
| --- | --- | --- |
| Coverage families | Missing request shape, object, state, sink, protocol context, or cleanup | Every family is present in the prerequisite registry; missing material becomes `waiting-prerequisite`. |
| Route collection | Dynamic route parameter unavailable | Search current producers and binding slots before recording an evidence-backed blocker. |
| UI controls | Unknown or side-effecting control | Classify the control and discover a cleanup-safe transaction before execution. |
| Authorization | Missing object ID, parent, subject, role evidence, or second principal | Continue all single-account modes; isolate only genuine cross-principal capability as external. |
| Identity and session | Missing challenge, ticket, pre-auth session, callback, or browser context | Trace producer-to-consumer binding rather than treating one response as a completed test. |
| Injection and browser | Missing input position, parser, render, preview, publish, or persistent sink | Discover the concrete consumer before payload selection or a negative conclusion. |
| Server-side and files | Missing URL/XML/converter/upload key/read/activate/delete/OAST context | Build the full consumption and cleanup chain; external OAST remains interim. |
| API protocols | Missing operation or message shape | Discover runtime traffic or current documentation; inventory alone does not satisfy execution. |
| Business logic | Missing eligibility, quota, approval state, idempotency baseline, or safe concurrency context | Discover current state and self-owned reversible objects before testing. |
| Platform exposure | Missing concrete endpoint, protected response, credentialed browser context, cache participant, or management entry | Run a safe baseline where possible; otherwise continue prerequisite discovery. |
| Runner | Missing raw template, mutation prestate, rollback, field binding, WAF, or credential | Discoverable gaps return to the prerequisite queue; external blockers remain `interim`. |
| Agent | `needs-agent` or unresolved candidate treated as a stopping point | Generate one action per safe search strategy and a separate saturation audit. |
| Auditor | `blocked` counted as resolved | Only `tested` and evidenced `not-applicable` satisfy coverage. |
| Reporting | A stopped scheduler presented as final | Emit `final=false` and `blocked-interim` with explicit unblock conditions. |
| Context continuity | Compaction drops blocked cases or producer clues | Preserve the prerequisite graph and sanitized provenance as canonical capsule sources. |

Regression coverage uses unrelated commerce, healthcare, and project-workflow
fixtures plus CORS, CSRF, SSRF, file consumption, persistent browser sinks,
race, approval, and protocol prerequisite declarations. No target identifiers
or deployment-specific behavior are part of this audit.
