#!/usr/bin/env python3
"""Check traceability structure, not application correctness or real-device results."""
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path


IMPLEMENTATION = {"UNASSESSED", "NOT_STARTED", "IN_PROGRESS", "IMPLEMENTED", "VERIFIED", "FAILED", "BLOCKED"}
VERIFICATION = {"PASS", "FAIL", "BLOCKED", "NOT_RUN", "N_A"}
REQUIRED = {"requirement_id", "priority", "implementation_status", "verification_status", "implementation_files", "actual_test_paths", "evidence_paths", "tested_commit", "environment", "blocker"}


def validate(root, matrix, prd):
    errors = []
    with matrix.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not REQUIRED.issubset(reader.fieldnames or []):
            return ["Missing required matrix columns"], []
        rows = list(reader)
    expected = set(re.findall(r"^\| (REQ-[A-Z]+-\d+) \|", prd.read_text(encoding="utf-8-sig"), re.M))
    if not expected:
        errors.append("PRD has no requirement baseline")
    ids = [row["requirement_id"] for row in rows]
    if set(ids) != expected:
        errors.append("Requirement IDs differ from PRD: " + str(sorted(set(ids) ^ expected)))
    for key, count in Counter(ids).items():
        if count != 1:
            errors.append(f"Duplicate requirement: {key}")
    root = root.resolve()
    for row in rows:
        key = row["requirement_id"]
        if None in row or any(value is None for value in row.values()):
            errors.append(f"{key}: malformed CSV row")
            continue
        implementation = row["implementation_status"]
        verification = row["verification_status"]
        if implementation not in IMPLEMENTATION or verification not in VERIFICATION:
            errors.append(f"{key}: invalid status")
        if row["priority"] != "MUST":
            errors.append(f"{key}: mandatory requirement priority changed")
        if verification == "N_A":
            errors.append(f"{key}: mandatory requirement cannot be excluded as N_A")
        if (implementation == "VERIFIED") != (verification == "PASS"):
            errors.append(f"{key}: VERIFIED and PASS must agree")
        if verification == "BLOCKED" or implementation == "BLOCKED":
            if not row["blocker"].strip():
                errors.append(f"{key}: BLOCKED requires a concrete blocker")
        for field in ["implementation_files", "actual_test_paths", "evidence_paths"]:
            for item in filter(None, (value.strip() for value in row[field].split(";"))):
                file = (root / item).resolve()
                if not file.is_relative_to(root) or not file.is_file():
                    errors.append(f"{key}: missing or out-of-project {field}: {item}")
        if implementation == "VERIFIED":
            for field in ["implementation_files", "actual_test_paths", "evidence_paths", "tested_commit", "environment"]:
                if not row[field].strip():
                    errors.append(f"{key}: VERIFIED requires {field}")
            if row["blocker"].strip():
                errors.append(f"{key}: VERIFIED cannot have an unresolved blocker")
    return errors, rows


def main():
    root = Path(__file__).resolve().parents[1]
    directory = root / "docs/requirements/infrascope"
    errors, rows = validate(root, directory / "05_需求追踪矩阵.csv", directory / "01_完整产品需求PRD.md")
    print(json.dumps({
        "check": "traceability structure only; NOT software acceptance",
        "requirements": len(rows), "verified": sum(row["implementation_status"] == "VERIFIED" for row in rows),
        "implementation": dict(Counter(row["implementation_status"] for row in rows)),
        "verification": dict(Counter(row["verification_status"] for row in rows)),
        "errors": errors,
    }, indent=2, ensure_ascii=False))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
