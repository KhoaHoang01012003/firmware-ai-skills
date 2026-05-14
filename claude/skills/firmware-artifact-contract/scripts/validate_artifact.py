#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path

COMMON_REQUIRED = ["schema_version", "generated_at", "generated_by", "source_inputs", "warnings", "errors"]
ARTIFACT_REQUIRED = {
    "firmware_manifest": ["artifact_type", "firmware_files", "rootfs_candidates"],
    "model_research": ["artifact_type", "claims"],
    "rootfs_profile": ["artifact_type", "architecture", "service_candidates"],
    "runtime_profile": ["artifact_type", "runtime_profile", "rootfs_mode"],
    "service_readiness": ["artifact_type", "ready_for_pentest", "services"],
    "api_smoke_results": ["artifact_type", "results"],
    "skill_context": ["artifact_type", "scope", "target_components", "entries"],
    "code_browser_findings": ["artifact_type", "findings"],
    "reverse_queue": ["artifact_type", "queue"],
    "hook_plan": ["artifact_type", "target_service", "capture_lanes", "workload"],
    "debug_plan": ["artifact_type", "target_process", "attach_mode", "intrusive_actions"],
    "probe_plan": ["artifact_type", "target", "sandbox_network", "payloads", "safety_constraints"],
    "verifier_report": ["artifact_type", "target_finding_id", "verdict", "reproduction_status", "evidence_labels", "duplicate_checks", "disclosure_status"],
    "observation_record": ["schema_version", "timestamp_utc", "component", "event_type", "label", "behavior_claim_allowed", "source_artifact", "risk_notes", "artifact_sensitivity"],
    "finding_record": ["schema_version", "timestamp_utc", "finding_id", "title", "component", "hypothesis", "severity_hypothesis", "evidence", "reproduction_status", "cve_claim_allowed", "verifier_report", "artifact_sensitivity"],
    "skill_registry": ["artifact_type", "skills"],
    "starter_request": ["artifact_type", "input_artifact", "authorization_scope", "safety_boundary", "requested_goal", "handoff_skill"],
    "next_skill_decision": ["artifact_type", "decision_id", "selected_skill", "skipped_skills", "required_inputs_satisfied", "expected_evidence_gain", "reentry_condition"],
    "hypothesis_ledger": ["artifact_type", "hypotheses"],
    "target_selection": ["artifact_type", "targets"],
    "discovery_plan": ["artifact_type", "evidence_level", "next_actions"],
    "binary_inventory": ["artifact_type", "binaries"],
    "service_inventory": ["artifact_type", "services"],
    "attack_surface_graph": ["artifact_type", "nodes", "edges"],
    "input_vectors": ["artifact_type", "vectors"],
    "input_path_chains": ["artifact_type", "chains"],
    "sink_source_map": ["artifact_type", "sources", "sinks", "chains"],
    "service_state_map": ["artifact_type", "services", "auth_boundaries", "preconditions"],
    "crash_analysis": ["artifact_type", "crash_id", "root_cause_status"],
    "exploitability_assessment": ["artifact_type", "candidate_id", "evidence_level", "primitive", "impact", "constraints", "auth_requirement", "reproducibility"],
    "duplicate_check": ["artifact_type", "candidate_id", "checked_sources", "overlap_status"],
    "candidate_report": ["artifact_type", "candidate_id", "evidence_level", "exploitability_assessment", "duplicate_check"],
}
RUNTIME_PROFILES = {"qemu-user", "qemu-system", "native-container", "device-ssh", "static-only"}
ROOTFS_MODES = {"rootfs_rw", "rootfs_ro", "static-only"}
SERVICE_CLASSES = {"required", "optional", "hardware_blocked", "mocked", "known_broken"}
READINESS_VALUES = {"ready", "degraded", "blocked", "not_applicable"}
OBSERVATION_LABELS = {"planned_static_analysis", "planned_runtime_live_hook", "planned_runtime_live_debugger", "observed_static_artifact", "observed_runtime_qemu", "observed_runtime_live_hook", "observed_runtime_live_debugger", "observed_qiling_target", "qiling_hooked_behavior", "sandbox_generated", "mocked_behavior", "verified", "unverified", "blocked"}
SENSITIVITY_VALUES = {"public_reference", "local_metadata", "local_sensitive", "secret_material", "firmware_proprietary"}
NON_RUNTIME_TRUTH_LABELS = {"planned_static_analysis", "planned_runtime_live_hook", "planned_runtime_live_debugger", "observed_static_artifact", "observed_qiling_target", "qiling_hooked_behavior", "sandbox_generated", "mocked_behavior", "unverified", "blocked"}
LIVE_OR_VERIFIED_LABELS = {"observed_runtime_qemu", "observed_runtime_live_hook", "observed_runtime_live_debugger", "verified"}
DEBUG_ATTACH_MODES = {"host-qemu-attach", "guest-gdbstub", "qemu-system-gdbstub", "gdbserver", "qiling-debugger", "static-blocked"}
SANDBOX_NETWORK_MODES = {"disabled", "explicitly_enabled", "blocked"}
FINDING_REPRODUCTION_STATUSES = {"hypothesis", "reproduced", "not_reproduced", "blocked", "duplicate_known_issue"}
VERIFIER_VERDICTS = {"verified", "unverified", "duplicate_known", "blocked", "rejected"}
DISCLOSURE_STATUSES = {"internal_triage", "vendor_report_planned", "vendor_reported", "public_reference_only", "not_for_disclosure"}
EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 1


def require_fields(data: dict, fields: list[str]) -> list[str]:
    return [field for field in fields if field not in data]


def load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    records: list[dict] = []
    errors: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"line {line_number}: record must be an object")
            continue
        records.append(value)
    if not records and not errors:
        errors.append("JSONL artifact has no records")
    return records, errors


def validate_observation_record(data: dict, prefix: str = "record") -> list[str]:
    errors: list[str] = []
    errors.extend(f"{prefix}.{field} is required" for field in require_fields(data, ARTIFACT_REQUIRED["observation_record"]))
    if data.get("schema_version") != "1.0.0":
        errors.append(f"{prefix}.schema_version must be 1.0.0")
    if data.get("label") not in OBSERVATION_LABELS:
        errors.append(f"{prefix}.label has invalid value")
    if data.get("artifact_sensitivity") not in SENSITIVITY_VALUES:
        errors.append(f"{prefix}.artifact_sensitivity has invalid value")
    if data.get("label") in NON_RUNTIME_TRUTH_LABELS and data.get("behavior_claim_allowed") is True:
        errors.append(f"{prefix}.behavior_claim_allowed must be false for {data.get('label')}")
    if not isinstance(data.get("risk_notes", []), list):
        errors.append(f"{prefix}.risk_notes must be a list")
    return errors


def validate_finding_record(data: dict, prefix: str = "record") -> list[str]:
    errors: list[str] = []
    errors.extend(f"{prefix}.{field} is required" for field in require_fields(data, ARTIFACT_REQUIRED["finding_record"]))
    if data.get("schema_version") != "1.0.0":
        errors.append(f"{prefix}.schema_version must be 1.0.0")
    if data.get("artifact_sensitivity") not in SENSITIVITY_VALUES:
        errors.append(f"{prefix}.artifact_sensitivity has invalid value")
    if data.get("reproduction_status") not in FINDING_REPRODUCTION_STATUSES:
        errors.append(f"{prefix}.reproduction_status has invalid value")
    if not isinstance(data.get("evidence", []), list):
        errors.append(f"{prefix}.evidence must be a list")
    if data.get("cve_claim_allowed") is True:
        if data.get("reproduction_status") != "reproduced":
            errors.append(f"{prefix}.cve_claim_allowed requires reproduced reproduction_status")
        if not data.get("verifier_report"):
            errors.append(f"{prefix}.verifier_report is required when cve_claim_allowed is true")
    if data.get("cve_id") and not data.get("verifier_report"):
        errors.append(f"{prefix}.verifier_report is required when cve_id is present")
    return errors


def validate_service_readiness(data: dict) -> list[str]:
    errors: list[str] = []
    services = data.get("services", [])
    if not isinstance(services, list):
        return ["services must be a list"]
    for index, service in enumerate(services):
        prefix = f"services[{index}]"
        service_missing = require_fields(service, ["service_name", "classification", "expected_process_patterns", "expected_ports", "expected_logs", "smoke_tests", "observed_processes", "observed_ports", "observed_log_signals", "smoke_result", "readiness"])
        errors.extend(f"{prefix}.{field} is required" for field in service_missing)
        if service.get("classification") not in SERVICE_CLASSES:
            errors.append(f"{prefix}.classification has invalid value")
        if service.get("readiness") not in READINESS_VALUES:
            errors.append(f"{prefix}.readiness has invalid value")
        if service.get("classification") == "required":
            for result in service.get("smoke_result", []):
                if result.get("status") == 500:
                    errors.append(f"{prefix} has unexplained HTTP 500 in smoke_result")
            if service.get("readiness") == "ready" and not service.get("observed_processes"):
                errors.append(f"{prefix} is ready without observed_processes")
            if service.get("readiness") == "ready" and not service.get("observed_ports"):
                errors.append(f"{prefix} is ready without observed_ports")
    if data.get("ready_for_pentest") is True and errors:
        errors.append("ready_for_pentest cannot be true while required readiness errors exist")
    return errors


def validate_common_artifact(data: dict, artifact_type: str) -> list[str]:
    errors: list[str] = []
    errors.extend(f"{field} is required" for field in require_fields(data, COMMON_REQUIRED))
    errors.extend(f"{field} is required" for field in require_fields(data, ARTIFACT_REQUIRED[artifact_type]))
    if data.get("schema_version") != "1.0.0":
        errors.append("schema_version must be 1.0.0")
    if data.get("artifact_type") != artifact_type:
        errors.append(f"artifact_type must be {artifact_type}")
    return errors


def validate_verifier_report(data: dict) -> list[str]:
    errors: list[str] = []
    if data.get("verdict") not in VERIFIER_VERDICTS:
        errors.append("verdict has invalid value")
    if data.get("reproduction_status") not in FINDING_REPRODUCTION_STATUSES:
        errors.append("reproduction_status has invalid value")
    if data.get("disclosure_status") not in DISCLOSURE_STATUSES:
        errors.append("disclosure_status has invalid value")
    evidence_labels = data.get("evidence_labels", [])
    if not isinstance(evidence_labels, list):
        errors.append("evidence_labels must be a list")
        evidence_labels = []
    if not isinstance(data.get("duplicate_checks", []), list):
        errors.append("duplicate_checks must be a list")
    if data.get("verdict") == "verified":
        if data.get("reproduction_status") != "reproduced":
            errors.append("verified verdict requires reproduced reproduction_status")
        if not LIVE_OR_VERIFIED_LABELS.intersection(set(evidence_labels)):
            errors.append("verified verdict requires live runtime or verified evidence")
    return errors


def validate_discovery_artifact(data: dict, artifact_type: str) -> list[str]:
    errors: list[str] = []
    if data.get("evidence_level") and data.get("evidence_level") not in EVIDENCE_LEVELS:
        errors.append("evidence_level has invalid value")
    if artifact_type == "next_skill_decision":
        if data.get("required_inputs_satisfied") is False and not data.get("warnings") and not data.get("errors"):
            errors.append("required_inputs_satisfied=false requires blocker-like warning or error text")
        if not data.get("expected_evidence_gain"):
            errors.append("expected_evidence_gain is required")
    if artifact_type == "exploitability_assessment":
        confirmed = str(data.get("impact", "")).lower().startswith("confirmed") or data.get("impact_confirmed") is True
        if confirmed and data.get("evidence_level") not in {"E6", "E7", "E8"}:
            errors.append("confirmed impact requires E6 or higher exploitability evidence")
    if artifact_type == "duplicate_check":
        checked_sources = data.get("checked_sources", [])
        if not isinstance(checked_sources, list) or not checked_sources:
            errors.append("checked_sources must be a non-empty list")
        text = json.dumps(data)
        if CVE_RE.search(text) and not checked_sources:
            errors.append("CVE references require checked source provenance")
    if artifact_type == "candidate_report":
        if data.get("evidence_level") == "E8" and not data.get("duplicate_check"):
            errors.append("candidate_report cannot be E8 without duplicate_check")
        duplicate_check = data.get("duplicate_check")
        if isinstance(duplicate_check, dict) and not duplicate_check.get("overlap_status"):
            errors.append("candidate_report duplicate_check requires overlap_status")
        if data.get("cve_id") and not duplicate_check:
            errors.append("candidate_report cve_id requires duplicate_check source status")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--artifact-type", required=True, choices=sorted(ARTIFACT_REQUIRED))
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--jsonl", action="store_true", help="Validate newline-delimited JSON records")
    args = parser.parse_args(argv)

    if not args.artifact.exists():
        return fail(f"artifact not found: {args.artifact}")
    schema_file = args.schema_dir / f"{args.artifact_type}.schema.json"
    if not schema_file.exists():
        return fail(f"schema file not found: {schema_file}")

    if args.jsonl:
        if args.artifact_type not in {"observation_record", "finding_record"}:
            return fail("--jsonl is only supported for observation_record and finding_record")
        records, errors = load_jsonl(args.artifact)
        for index, record in enumerate(records):
            if args.artifact_type == "observation_record":
                errors.extend(validate_observation_record(record, prefix=f"records[{index}]"))
            else:
                errors.extend(validate_finding_record(record, prefix=f"records[{index}]"))
        if errors:
            for error in errors:
                print(error, file=sys.stderr)
            return 1
        print(f"valid {args.artifact_type}: {args.artifact}")
        return 0

    try:
        data = json.loads(args.artifact.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return fail(f"invalid JSON: {exc}")

    if args.artifact_type == "observation_record":
        errors = validate_observation_record(data)
    elif args.artifact_type == "finding_record":
        errors = validate_finding_record(data)
    else:
        errors = validate_common_artifact(data, args.artifact_type)

    if args.artifact_type == "runtime_profile":
        if data.get("runtime_profile") not in RUNTIME_PROFILES:
            errors.append("runtime_profile has invalid value")
        if data.get("rootfs_mode") not in ROOTFS_MODES:
            errors.append("rootfs_mode has invalid value")
    if args.artifact_type == "service_readiness":
        errors.extend(validate_service_readiness(data))
    if args.artifact_type == "debug_plan" and data.get("attach_mode") not in DEBUG_ATTACH_MODES:
        errors.append("attach_mode has invalid value")
    if args.artifact_type == "probe_plan" and data.get("sandbox_network") not in SANDBOX_NETWORK_MODES:
        errors.append("sandbox_network has invalid value")
    if args.artifact_type == "verifier_report":
        errors.extend(validate_verifier_report(data))
    if args.artifact_type in {"next_skill_decision", "discovery_plan", "exploitability_assessment", "duplicate_check", "candidate_report"}:
        errors.extend(validate_discovery_artifact(data, args.artifact_type))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"valid {args.artifact_type}: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
