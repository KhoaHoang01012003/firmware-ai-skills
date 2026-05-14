#!/usr/bin/env python3
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import validate_memory


def slug(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "memory"


def first_applies_to(frontmatter: dict, key: str, default: str) -> str:
    applies_to = frontmatter.get("applies_to", {})
    if isinstance(applies_to, dict):
        values = applies_to.get(key, [])
        if values:
            return slug(str(values[0]))
    return default


def destination(workspace: Path, frontmatter: dict, draft: Path) -> Path:
    memory_type = frontmatter["memory_type"]
    filename = slug(draft.stem) + ".md"
    if memory_type == "product":
        vendor = first_applies_to(frontmatter, "vendors", "generic-vendor")
        model = first_applies_to(frontmatter, "models", "generic-model")
        return workspace / "product-skills" / vendor / model / filename
    if memory_type == "service":
        service = first_applies_to(frontmatter, "services", "generic-service")
        return workspace / "service-skills" / service / filename
    tool = first_applies_to(frontmatter, "tools", first_applies_to(frontmatter, "runtimes", "generic-tool"))
    return workspace / "tool-skills" / tool / filename


def index_record(path: Path, workspace: Path, frontmatter: dict) -> dict:
    evidence = frontmatter.get("evidence", {})
    return {
        "path": path.relative_to(workspace).as_posix(),
        "memory_type": frontmatter.get("memory_type"),
        "title": frontmatter.get("title"),
        "status": "active",
        "tags": frontmatter.get("tags", []),
        "applies_to": frontmatter.get("applies_to", {}),
        "artifact_sensitivity": frontmatter.get("artifact_sensitivity"),
        "last_verified": evidence.get("verified_on") if isinstance(evidence, dict) else "",
    }


def load_index(workspace: Path) -> dict:
    index_path = workspace / "memory-index.json"
    if index_path.exists():
        return json.loads(index_path.read_text(encoding="utf-8"))
    return {"schema_version": "1.0.0", "generated_at": "", "workspace_root": str(workspace), "memories": []}


def save_index(workspace: Path, index: dict) -> None:
    index["schema_version"] = "1.0.0"
    index["generated_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    index["workspace_root"] = str(workspace)
    (workspace / "memory-index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Promote a firmware memory draft")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--draft", type=Path, required=True)
    parser.add_argument("--update-existing", action="store_true")
    args = parser.parse_args(argv)

    errors = validate_memory.validate(args.draft)
    if errors:
        for error in errors:
            print(error)
        return 1
    frontmatter, _, _ = validate_memory.parse_frontmatter(args.draft.read_text(encoding="utf-8"))
    frontmatter["status"] = "active"
    dest = destination(args.workspace, frontmatter, args.draft)
    if dest.exists() and not args.update_existing:
        print(f"destination exists: {dest}")
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = args.draft.read_text(encoding="utf-8").replace("status: draft", "status: active", 1)
    dest.write_text(text, encoding="utf-8")

    index = load_index(args.workspace)
    record = index_record(dest, args.workspace, frontmatter)
    index["memories"] = [item for item in index.get("memories", []) if item.get("path") != record["path"]]
    index["memories"].append(record)
    index["memories"] = sorted(index["memories"], key=lambda item: item["path"])
    save_index(args.workspace, index)
    print(f"promoted memory: {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
