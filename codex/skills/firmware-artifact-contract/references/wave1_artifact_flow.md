# Wave 1 Artifact Flow

1. `firmware-intake-extracting` writes `firmware_manifest.json`, `extraction_tree.txt`, `hashes.txt`, and `known_limitations.md`.
2. `firmware-model-research` reads `firmware_manifest.json` and writes `model_research.json`, `behavior_assumptions.md`, and `research_sources.md`.
3. `firmware-rootfs-profiling` reads `firmware_manifest.json` and `model_research.json`, then writes `rootfs_profile.json`, `service_graph.json`, `skill_context.json`, and `interesting_targets.json`.
4. `firmware-service-emulating` reads Wave 1 artifacts and writes `runtime_profile.json`, `service_readiness.json`, `api_smoke_results.json`, `runtime_warnings.json`, and `known_limitations.md`.
5. If readiness fails, `firmware-service-emulating` writes `emulation_blocker.json` and switches to `superpowers:systematic-debugging`.

Wave 1 is complete only when the runtime is `ready_for_pentest=true` or a blocker explains why pentesting cannot proceed.
