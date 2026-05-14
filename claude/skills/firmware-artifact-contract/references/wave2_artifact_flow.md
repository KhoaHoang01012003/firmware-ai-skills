# Wave 2 Artifact Flow

1. `firmware-code-browsing` reads `rootfs_profile.json`, `service_graph.json`, and optional `model_research.json`, then writes `skill_context.json`, `code_browser_findings.jsonl`, `reverse_queue.json`, and `known_limitations.md`.
2. `firmware-runtime-hooking` reads `runtime_profile.json`, `service_readiness.json`, and workload scope, then writes `hook_plan.json`, redacted extracts, `observations.jsonl`, and `known_limitations.md`.
3. `firmware-debugging` reads runtime and hook evidence, then writes `debug_plan.json`, `gdb_commands.gdb`, `gdb_transcript.txt`, `debug_observations.jsonl`, and `known_limitations.md`.
4. Static code browsing, Qiling-only, mocked, sandbox, and planned observations must set `behavior_claim_allowed=false`.
5. Live runtime hook/debug observations may set `behavior_claim_allowed=true` only when the source artifact proves the target workload was observed.

Wave 2 is complete only when the LLM has compact static context plus either live runtime hook/debug evidence or a blocker explaining why live evidence could not be captured.
