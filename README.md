# Firmware AI Dual Skills

Firmware discovery and emulation skills for both Codex and Claude.

This repository keeps two installable copies of the same firmware workflow:

- `codex/skills/firmware-*` for Codex.
- `claude/skills/firmware-*` for Claude Code.

The skill names intentionally match across both platforms so a workflow can move between Codex and Claude without changing the routing language.

## Emulation Success Standard

For UI-bearing firmware, these skills do not treat a boot log, shell, or guest-loopback port as successful emulation by itself.

Emulation is successful only when the artifacts account for:

- required services and processes observed at runtime;
- host/browser reachability;
- real UI static assets and API routing;
- login/auth flow without storing credentials;
- key feature routes marked usable, degraded, or blocked;
- claim scope for full-system, qemu-user, chroot, container, proxy, or live-device lanes.

The important artifacts are:

- `runtime_readiness.json`
- `reachable_services.json`
- `ui_access_status.json`
- `ui_runtime_observation.json`
- `emulation_success.json`

## Install

From this repo root:

```powershell
# Install both sets
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Target both

# Codex only
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Target codex

# Claude only
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Target claude
```

The installer copies only `firmware-*` skill folders. Existing target folders are backed up before overwrite.

## Use

In Codex or Claude, start with:

```text
Use firmware-start with <firmware path or extracted rootfs>. Goal: emulate full services, open UI in browser, login, and use functions.
```

Or resume a current artifact:

```text
Continue this firmware analysis. The emulation success gate requires host/browser UI access, login flow, and usable/degraded feature map.
```

The expected routing is:

1. `firmware-start`
2. `firmware-discovery-orchestrator`
3. `firmware-service-state-discovery`
4. `firmware-service-emulation`
5. `firmware-runtime-observation`
6. exploitability or safe probing skills only after the runtime/UI gates are documented.

## Safety

Use only on firmware and runtimes you are authorized to test. Do not store real credentials, tokens, cookies, private certificates, raw firmware dumps, or proprietary traces in public artifacts or reports.

