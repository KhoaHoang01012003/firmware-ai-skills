#!/usr/bin/env python3
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


WORD = re.compile(r"[A-Za-z0-9_.+-]{2,}")


def load_json(path: Path | None):
    if not path:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def collect_terms(value) -> set[str]:
    terms: set[str] = set()
    if value is None:
        return terms
    if isinstance(value, dict):
        for key, item in value.items():
            terms.update(collect_terms(key))
            terms.update(collect_terms(item))
        return terms
    if isinstance(value, list):
        for item in value:
            terms.update(collect_terms(item))
        return terms
    for match in WORD.findall(str(value).lower()):
        terms.add(match)
    return terms


def values_from_record(record: dict) -> set[str]:
    values = set()
    for key in ("tags",):
        values.update(str(item).lower() for item in record.get(key, []) if str(item).strip())
    values.update(applies_to_terms(record))
    values.update(collect_terms(record.get("title", "")))
    return values


def applies_to_terms(record: dict) -> set[str]:
    values = set()
    applies_to = record.get("applies_to", {})
    if not isinstance(applies_to, dict):
        return values
    for items in applies_to.values():
        if isinstance(items, list):
            values.update(str(item).lower() for item in items if str(item).strip())
    return values


def recommendation(score: int) -> str:
    if score >= 2:
        return "read_now"
    if score == 1:
        return "read_if_blocked"
    return "skip"


def suggest(index: dict, artifact_terms: set[str]) -> list[dict]:
    suggestions = []
    for record in index.get("memories", []):
        if record.get("status") not in {"active", "needs_revalidation"}:
            continue
        memory_terms = values_from_record(record)
        matched = sorted(memory_terms.intersection(artifact_terms))
        score = len(matched)
        core_match = bool(applies_to_terms(record).intersection(artifact_terms))
        load = "read_now" if core_match and score > 0 else recommendation(score)
        if load == "skip":
            continue
        suggestions.append(
            {
                "memory_path": record["path"],
                "memory_type": record.get("memory_type", ""),
                "score": score,
                "matched_terms": matched,
                "matched_artifacts": sorted(artifact_terms.intersection(matched)),
                "reason": f"matched {score} term(s): {', '.join(matched)}",
                "load_recommendation": load,
            }
        )
    return sorted(suggestions, key=lambda item: (-item["score"], item["memory_path"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Suggest firmware memory files from artifacts")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--model-research", type=Path)
    parser.add_argument("--rootfs-profile", type=Path)
    parser.add_argument("--service-graph", type=Path)
    parser.add_argument("--runtime-profile", type=Path)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--verifier-report", type=Path)
    parser.add_argument("--output", type=Path, default=Path("memory_suggestions.json"))
    args = parser.parse_args(argv)

    index_path = args.workspace / "memory-index.json"
    index = load_json(index_path)
    source_paths = [
        args.model_research,
        args.rootfs_profile,
        args.service_graph,
        args.runtime_profile,
        args.observations,
        args.verifier_report,
    ]
    artifact_terms: set[str] = set()
    for path in source_paths:
        if not path:
            continue
        if path.suffix == ".jsonl":
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    artifact_terms.update(collect_terms(json.loads(line)))
        else:
            artifact_terms.update(collect_terms(load_json(path)))

    output = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_inputs": [str(path) for path in source_paths if path],
        "suggestions": suggest(index, artifact_terms),
    }
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"wrote memory suggestions: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
