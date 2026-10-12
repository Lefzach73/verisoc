"""Run one explicit offline preparation, status check or supplied-review scoring step."""

import argparse
import json
from pathlib import Path

from verisoc.evaluation.v05_workflow import (
    resume_workflow,
    start_workflow,
    workflow_status,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser(
        "start", help="Freeze inputs, export blank forms and run matched mocks"
    )
    for name in ("manifest", "contamination", "plan", "out"):
        start.add_argument(f"--{name}", type=Path, required=True)
    start.add_argument("--reviewer-one", required=True)
    start.add_argument("--reviewer-two", required=True)
    start.add_argument("--repo", type=Path, default=Path("."))
    status = commands.add_parser("status", help="Verify immutable files and report remaining gates")
    status.add_argument("--workflow", type=Path, required=True)
    resume = commands.add_parser("resume", help="Validate supplied human-review files and score")
    resume.add_argument("--workflow", type=Path, required=True)
    resume.add_argument("--submissions", type=Path, action="append", required=True)
    resume.add_argument("--adjudications", type=Path)
    resume.add_argument("--out", type=Path, required=True)
    resume.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    try:
        if args.command == "start":
            result = start_workflow(
                args.manifest,
                args.contamination,
                args.plan,
                (args.reviewer_one, args.reviewer_two),
                args.repo.resolve(),
                args.out,
            )
        elif args.command == "status":
            result = workflow_status(args.workflow)
        else:
            result = resume_workflow(
                args.workflow,
                tuple(args.submissions),
                args.adjudications,
                args.repo.resolve(),
                args.out,
            )
    except (ValueError, OSError, KeyError, TypeError):
        print(json.dumps(dict(status="FAILED", reason="invalid_or_changed_workflow_input")))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["status"] == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
