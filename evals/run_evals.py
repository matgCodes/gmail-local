"""Automated Evaluation Benchmark Runner for gmail-local."""

import sys
import time
from pathlib import Path

import pytest


def main() -> int:
    print("=" * 78)
    print("  GMAIL LOCAL AGENT HARDENING EVALUATION BENCHMARK")
    print("=" * 78)
    print(f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print(f"Directory: {Path(__file__).parent.resolve()}")
    print("-" * 78)

    eval_dir = str(Path(__file__).parent)

    # Run pytest on the evals suite
    args = [
        "-q",
        "--tb=short",
        eval_dir,
    ]

    retcode = pytest.main(args)

    print("-" * 78)
    if retcode == 0:
        print("  ALL EVALUATIONS PASSED: AGENT CONTRACTS & DEFENSES VERIFIED")
    else:
        print(f"  EVALUATION FAILED (exit code: {retcode})")
    print("=" * 78)
    return retcode


if __name__ == "__main__":
    sys.exit(main())
