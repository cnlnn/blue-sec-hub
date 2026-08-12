# Security Benchmark Results

Release quality separates live behavioral benchmarks from platform contracts.
Codex and Claude run the fixed Juice Shop, crAPI, WebGoat, and minimal SPA/API
fixtures three times on every supported operating system. All nine agent
platforms must separately pass their install, MCP, hook, checkpoint, and
restore contracts.

GitHub may publish an `artifact-only` source release after repository validation and all
nine platform contracts pass. Such a release is installable but explicitly does not claim
the live Codex/Claude behavioral certification described below.

```bash
python scripts/benchmark_suite.py \
  --run <fixture-agent-platform-run.json> \
  --agent-contract codex \
  --agent-contract claude \
  --agent-contract gemini \
  --agent-contract grok \
  --agent-contract opencode \
  --agent-contract openclaw \
  --agent-contract hermes \
  --agent-contract trae \
  --agent-contract trae-cn \
  --out benchmarks/latest-result.json
python scripts/quality_gate.py benchmarks/latest-result.json
```

Run files contain only fixture IDs, agent and operating-system identifiers,
anonymous finding IDs, timings, completion state, and corruption counters.
