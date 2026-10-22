"""python -m tmcheck MODEL.yaml"""


import json
import sys
from dataclasses import asdict

from tmcheck.core import (
    ModelError, coverage_gaps, load_model, policy_findings, rank, validate,
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2
    path = argv[0]

    try:
        model = load_model(path)
    except ModelError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    issues = validate(model)
    gaps = coverage_gaps(model)
    policy = policy_findings(model)
    ranked = rank(model)

    report = {
        "issues": [asdict(item) for item in issues],
        "gaps": [asdict(item) for item in gaps],
        "policy": [asdict(item) for item in policy],
        "ranked": [asdict(item) for item in ranked],
    }
    
    print(json.dumps(report, indent=2, default=str))
    return 1 if (issues or gaps or policy) else 0


if __name__ == "__main__":
    raise SystemExit(main())
