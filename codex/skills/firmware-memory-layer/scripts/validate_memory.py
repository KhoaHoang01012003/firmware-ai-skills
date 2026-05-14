#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path

REQUIRED_FRONTMATTER = {"memory_schema_version", "memory_type", "title", "status", "tags", "applies_to", "evidence", "artifact_sensitivity"}
REQUIRED_HEADINGS = ["## Use When", "## Durable Pattern", "## Evidence", "## Limits", "## Safety"]
MEMORY_TYPES = {"product", "service", "tool", "exploitability-pattern", "surface-fingerprint", "service-reachability-pattern", "input-parser-pattern", "sink-pattern", "crash-signature", "auth-boundary-pattern", "runtime-hooking-recipe", "debugging-recipe", "false-positive-pattern"}
STATUSES = {"draft", "active", "deprecated", "needs_revalidation"}
SENSITIVITY = {"public_reference", "local_metadata", "local_sensitive"}
LIVE_OR_VERIFIED = {"observed_runtime_qemu", "observed_runtime_live_hook", "observed_runtime_live_debugger", "verified"}
SECRET_PATTERNS = [re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I), re.compile(r"Cookie:\s*[^\n=]+=.{8,}", re.I), re.compile(r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----"), re.compile(r"-----BEGIN CERTIFICATE-----"), re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}")]
LONG_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{160,}(?![A-Za-z0-9+/=])")
DISCOVERY_PATTERN_TYPES = MEMORY_TYPES - {"product", "service", "tool"}


def fail(errors: list[str]) -> int:
    for error in errors:
        print(error, file=sys.stderr)
    return 1


def parse_scalar(value: str):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [item.strip().strip("\"'") for item in inner.split(",") if item.strip()]
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value.strip("\"'")


def parse_frontmatter(text: str) -> tuple[dict, str, list[str]]:
    if not text.startswith("---\n"):
        return {}, text, ["frontmatter block is required"]
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text, ["closing frontmatter marker is required"]
    raw = text[4:end].splitlines()
    body = text[end + 4 :]
    data: dict = {}
    current_parent = None
    for line in raw:
        if not line.strip():
            continue
        if not line.startswith(" "):
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if value:
                data[key] = parse_scalar(value)
                current_parent = None
            else:
                data[key] = {}
                current_parent = key
            continue
        if current_parent is None:
            continue
        stripped = line.strip()
        key, sep, value = stripped.partition(":")
        if not sep:
            continue
        data[current_parent][key.strip()] = parse_scalar(value)
    return data, body, []


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    frontmatter, body, parse_errors = parse_frontmatter(text)
    errors.extend(parse_errors)
    if parse_errors:
        return errors

    missing = sorted(REQUIRED_FRONTMATTER - set(frontmatter))
    errors.extend(f"{field} is required" for field in missing)
    if frontmatter.get("memory_schema_version") != "1.0.0":
        errors.append("memory_schema_version must be 1.0.0")
    if frontmatter.get("memory_type") not in MEMORY_TYPES:
        errors.append("memory_type has invalid value")
    if frontmatter.get("status") not in STATUSES:
        errors.append("status has invalid value")
    if frontmatter.get("artifact_sensitivity") not in SENSITIVITY:
        errors.append("artifact_sensitivity has invalid value")
    if not isinstance(frontmatter.get("tags", []), list):
        errors.append("tags must be an inline list")
    if not isinstance(frontmatter.get("applies_to", {}), dict):
        errors.append("applies_to must be a mapping")
    if not isinstance(frontmatter.get("evidence", {}), dict):
        errors.append("evidence must be a mapping")

    for heading in REQUIRED_HEADINGS:
        if heading not in body:
            errors.append(f"{heading} heading is required")

    evidence = frontmatter.get("evidence", {})
    source_artifacts = evidence.get("source_artifacts", []) if isinstance(evidence, dict) else []
    source_urls = evidence.get("source_urls", []) if isinstance(evidence, dict) else []
    if not source_artifacts and not source_urls:
        errors.append("source_artifacts or source_urls evidence is required")
    for source in source_artifacts:
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = Path.cwd() / source_path
        if not source_path.exists():
            errors.append(f"source artifact does not exist: {source}")
    verified_on = evidence.get("verified_on") if isinstance(evidence, dict) else None
    if not isinstance(verified_on, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", verified_on):
        errors.append("evidence.verified_on must be an exact YYYY-MM-DD date")

    evidence_labels = set(evidence.get("evidence_labels", [])) if isinstance(evidence, dict) else set()
    if frontmatter.get("behavior_claim") is True and not LIVE_OR_VERIFIED.intersection(evidence_labels):
        errors.append("behavior_claim requires live runtime or verified evidence")
    if frontmatter.get("memory_type") in DISCOVERY_PATTERN_TYPES and frontmatter.get("status") == "active" and not LIVE_OR_VERIFIED.intersection(evidence_labels):
        errors.append("active discovery patterns require live runtime or verified evidence")

    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            errors.append("memory contains secret-like material")
            break
    if LONG_BLOB.search(body):
        errors.append("memory contains a long encoded or raw blob")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate firmware memory Markdown")
    parser.add_argument("memory_file", type=Path)
    args = parser.parse_args(argv)
    errors = validate(args.memory_file)
    if errors:
        return fail(errors)
    print(f"valid memory: {args.memory_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
