# Hermes Adapter

Blue Sec Hub installs the canonical Skills into `~/.hermes/skills` and registers the
`blue-sec-hub` MCP server with `hermes mcp add`.

Task state is written through `record_security_context_event` and checkpointed after
state changes. The generated `blue-sec-hub-hooks.json` describes the verified
`on_pre_compress` and `on_session_start` integration points without replacing the
user's selected exclusive Hermes memory provider. Until Hermes supports composable
memory-provider hooks, Doctor reports this native hook portion as `contract-ready`;
event checkpoints and MCP restoration remain active.
