# Wave 3 Artifact Flow

1. `firmware-probing-sandbox` reads `skill_context.json`, runtime observations, hook/debug evidence, and a scoped hypothesis, then writes `probe_plan.json`, generated local probes, `sandbox_observations.jsonl`, and hypothesis records in `findings.jsonl`.
2. Sandbox observations use `sandbox_generated` and `behavior_claim_allowed=false` until separate live runtime evidence verifies them.
3. `firmware-cve-verification` reads static findings, runtime observations, debugger/hook artifacts, sandbox results, model research, and public vulnerability context.
4. Verification writes `verifier_report.json`, updates `findings.jsonl`, and may write `cve_candidate_report.md` only for verified or carefully bounded candidate cases.
5. Static suspicion, Qiling-only behavior, sandbox-only output, mocked behavior, or public writeups alone cannot produce a `verified` verdict.

Wave 3 is complete only when each candidate is `verified`, `unverified`, `duplicate_known`, or `blocked` with provenance and duplicate-check status recorded.
