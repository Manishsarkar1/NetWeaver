#!/usr/bin/env python3
"""
Compare the VANTA project idea described in the docs against the current codebase.

What this script does:
1. Runs the local unit test suite.
2. Checks whether the architecture/components/features promised in the docs
   are reflected in the current implementation.
3. Produces a human-readable Markdown report and an optional JSON report.

Example:
    python compare_architecture.py
    python compare_architecture.py --skip-tests --json-out reports/vanta_alignment.json
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"


@dataclass
class CheckResult:
    name: str
    category: str
    expected: str
    status: str
    evidence: list[str]
    notes: str = ""


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def has_pattern(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE) is not None


def collect_matches(path: Path, patterns: Iterable[str]) -> list[str]:
    text = read_text(path)
    matches: list[str] = []
    for pattern in patterns:
        if has_pattern(text, pattern):
            matches.append(path.name)
    return matches


def count_matches(paths: Iterable[Path], patterns: Iterable[str]) -> list[str]:
    evidence: list[str] = []
    for path in paths:
        path_text = read_text(path)
        if any(has_pattern(path_text, pattern) for pattern in patterns):
            evidence.append(path.name)
    return evidence


def run_unit_tests() -> dict:
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return {
        "command": " ".join(command),
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def build_checks() -> list[CheckResult]:
    controller = ROOT / "ultimate_mtd_controller.py"
    attack_simulator = ROOT / "attack_simulator.py"
    benchmark_suite = ROOT / "benchmark_suite.py"
    tests_dir = list((ROOT / "tests").glob("*.py"))
    core_dir = list((ROOT / "vanta_core").glob("*.py"))

    controller_text = read_text(controller)
    attack_text = read_text(attack_simulator)
    benchmark_text = read_text(benchmark_suite)

    checks: list[CheckResult] = []

    def add_check(
        name: str,
        category: str,
        expected: str,
        evidence_patterns: dict[Path, list[str]],
        notes: str = "",
        partial_patterns: dict[Path, list[str]] | None = None,
        forced_status: str | None = None,
    ) -> None:
        evidence: list[str] = []
        matched_patterns = 0
        total_patterns = sum(len(patterns) for patterns in evidence_patterns.values())
        for path, patterns in evidence_patterns.items():
            path_text = read_text(path)
            path_matched = False
            for pattern in patterns:
                if has_pattern(path_text, pattern):
                    matched_patterns += 1
                    path_matched = True
            if path_matched:
                evidence.append(path.name)

        status = "missing"
        if matched_patterns == total_patterns and total_patterns > 0:
            status = "implemented"
        elif matched_patterns > 0:
            status = "partial"

        if status == "missing" and partial_patterns:
            partial_evidence = []
            for path, patterns in partial_patterns.items():
                partial_evidence.extend(collect_matches(path, patterns))
            if partial_evidence:
                status = "partial"
                evidence.extend(partial_evidence)

        if forced_status is not None:
            status = forced_status

        evidence = sorted(set(evidence))
        checks.append(
            CheckResult(
                name=name,
                category=category,
                expected=expected,
                status=status,
                evidence=evidence,
                notes=notes,
            )
        )

    add_check(
        name="SDN controller and VIP morphing",
        category="Core architecture",
        expected="The controller should implement OpenFlow handling, VIP mapping, and IP morphing.",
        evidence_patterns={
            controller: [
                r"class UltimateMTDController",
                r"ofproto_v1_3",
                r"real_to_virtual",
                r"virtual_to_real",
                r"def morph_ip_pair",
            ]
        },
    )

    add_check(
        name="Threat-triggered defense",
        category="Core architecture",
        expected="Scan-like behavior should be detected and used to trigger defensive remorphing.",
        evidence_patterns={
            controller: [r"threat_detector", r"trigger='threat'|trigger=\"threat\""],
            ROOT / "vanta_core" / "defense.py": [r"class ThreatDetector", r"detect_port_scan"],
        },
    )

    add_check(
        name="Multiple morphing strategies",
        category="Core architecture",
        expected="Reply, time, packet-count, threat-triggered, and manual morphing should exist.",
        evidence_patterns={
            controller: [
                r"reply_triggered",
                r"time_based",
                r"packet_count_based",
                r"threat_triggered",
                r"manual",
            ],
            ROOT / "vanta_core" / "defense.py": [
                r"reply_triggered",
                r"time_based",
                r"packet_count_based",
                r"threat_triggered",
            ],
        },
    )

    add_check(
        name="Dashboard and APIs",
        category="User-facing architecture",
        expected="A dashboard and the documented API endpoints should be available.",
        evidence_patterns={
            controller: [
                r"SocketIO",
                r"@flask_app\.route\('/api/stats'",
                r"@flask_app\.route\('/api/mappings'",
                r"@flask_app\.route\('/api/strategy'",
                r"@flask_app\.route\('/api/morph/force'",
                r"@flask_app\.route\('/api/export/csv'",
                r"@flask_app\.route\('/api/export/json'",
                r"@flask_app\.route\('/api/export/pdf'",
            ]
        },
    )

    add_check(
        name="Attack simulation coverage",
        category="Validation tooling",
        expected="Attack simulator should cover the documented attack scenarios.",
        evidence_patterns={
            attack_simulator: [
                r"def port_scan",
                r"def syn_flood",
                r"def ping_flood",
                r"def reconnaissance",
            ]
        },
        partial_patterns={
            attack_simulator: [r"choices=\['port_scan', 'syn_flood', 'ping_flood', 'reconnaissance', 'all'\]"]
        },
        notes="Quick start mentions `brute_force`, but no `def brute_force` implementation or CLI choice exists.",
        forced_status="partial",
    )

    add_check(
        name="Benchmark coverage",
        category="Validation tooling",
        expected="Benchmark suite should expose latency, throughput, CPU, memory, flow-table, and strategy comparison measurements.",
        evidence_patterns={
            benchmark_suite: [
                r"def latency_benchmark",
                r"def throughput_benchmark",
                r"def cpu_memory_benchmark|resource_utilization",
                r"def strategy_comparison_benchmark",
            ]
        },
        partial_patterns={
            benchmark_suite: [r"choices=\['latency', 'throughput', 'cpu', 'memory', 'resource', 'strategy', 'all'\]"]
        },
        notes="Docs mention a dedicated flow-table benchmark, but the current CLI exposes resource and strategy modes instead.",
        forced_status="partial",
    )

    add_check(
        name="Authentication and session handling",
        category="Operational readiness",
        expected="The dashboard should have login/session support rather than being fully open.",
        evidence_patterns={
            controller: [
                r"LoginManager",
                r"login_user",
                r"logout_user",
                r"@login_required",
            ]
        },
    )

    add_check(
        name="Configurable runtime secrets",
        category="Operational readiness",
        expected="Runtime configuration should allow safer overrides instead of only hardcoded secrets.",
        evidence_patterns={
            controller: [
                r"load_runtime_config",
                r"VANTA_SECRET_KEY",
                r"VANTA_ADMIN_PASSWORD",
            ],
            ROOT / "vanta_core" / "config.py": [
                r"class RuntimeConfig",
                r"os\.getenv",
            ],
        },
    )

    add_check(
        name="Automated tests for core logic",
        category="Operational readiness",
        expected="Core logic should be backed by automated tests.",
        evidence_patterns={
            ROOT / "tests" / "test_defense.py": [
                r"class MorphingStrategyTests",
                r"class ThreatDetectorTests",
            ],
            ROOT / "tests" / "test_config.py": [r"class ConfigTests"],
        },
        notes="Coverage exists for extracted core logic, but not yet for the Flask API or full controller packet paths.",
        forced_status="partial",
    )

    add_check(
        name="Modular architecture",
        category="Architecture quality",
        expected="Core logic should be reusable outside the monolithic controller file.",
        evidence_patterns={
            ROOT / "vanta_core" / "__init__.py": [r"from \.config", r"from \.defense"],
            ROOT / "vanta_core" / "defense.py": [r"class MorphingStrategy", r"class ThreatDetector"],
            ROOT / "vanta_core" / "models.py": [r"class MorphEvent", r"class ThreatEvent"],
        },
        notes="The controller is still the main runtime entry point, but the logic extraction has started.",
        forced_status="partial",
    )

    add_check(
        name="Reproducible output artifacts",
        category="Research alignment",
        expected="Experiments should produce reusable result artifacts for comparison and reporting.",
        evidence_patterns={
            attack_simulator: [r"json\.dump", r"attack_.*\.json"],
            benchmark_suite: [r"benchmark_results_", r"json\.dump"],
        },
        notes="Artifacts exist, but there is still room to standardize result schemas and summary reports.",
        forced_status="partial",
    )

    documented_idea = [
        "SDN-driven VIP mapping and morphing",
        "Threat-triggered response",
        "Real-time dashboard and API",
        "Attack simulation suite",
        "Benchmarking suite",
        "Authentication and export features",
        "Reproducible experiment outputs",
    ]

    implemented_counter = Counter(check.status for check in checks)
    idea_alignment_score = round(
        ((implemented_counter["implemented"] + 0.5 * implemented_counter["partial"]) / len(checks)) * 100,
        1,
    )

    checks.append(
        CheckResult(
            name="Overall idea alignment",
            category="Summary",
            expected="The implemented architecture should reflect the project idea described in the docs.",
            status="implemented" if idea_alignment_score >= 80 else "partial" if idea_alignment_score >= 55 else "missing",
            evidence=documented_idea,
            notes=f"Weighted alignment score: {idea_alignment_score}%",
        )
    )

    return checks


def render_markdown(test_result: dict | None, checks: list[CheckResult]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary_counter = Counter(check.status for check in checks if check.category != "Summary")
    score_note = next((check.notes for check in checks if check.name == "Overall idea alignment"), "")

    lines = [
        "# VANTA Idea vs Existing Architecture Report",
        "",
        f"- Generated: {timestamp}",
        f"- Repository: `{ROOT}`",
        f"- Alignment summary: {score_note or 'N/A'}",
        "",
        "## Test Result",
    ]

    if test_result is None:
        lines.append("- Tests were skipped.")
    else:
        lines.extend(
            [
                f"- Command: `{test_result['command']}`",
                f"- Status: {'PASS' if test_result['passed'] else 'FAIL'}",
            ]
        )
        if test_result["stdout"]:
            lines.extend(["", "```text", test_result["stdout"], "```"])
        if test_result["stderr"]:
            lines.extend(["", "```text", test_result["stderr"], "```"])

    lines.extend(
        [
            "",
            "## Alignment Summary",
            f"- Implemented: {summary_counter['implemented']}",
            f"- Partial: {summary_counter['partial']}",
            f"- Missing: {summary_counter['missing']}",
            "",
            "## Detailed Comparison",
        ]
    )

    for check in checks:
        if check.category == "Summary":
            continue
        lines.extend(
            [
                f"### {check.name}",
                f"- Category: {check.category}",
                f"- Expected: {check.expected}",
                f"- Status: {check.status}",
                f"- Evidence: {', '.join(check.evidence) if check.evidence else 'None'}",
            ]
        )
        if check.notes:
            lines.append(f"- Notes: {check.notes}")
        lines.append("")

    gaps = [check for check in checks if check.status != "implemented" and check.category != "Summary"]
    lines.extend(["## Biggest Gaps"])
    if gaps:
        for check in gaps:
            lines.append(f"- {check.name}: {check.notes or check.expected}")
    else:
        lines.append("- No major gaps detected.")

    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the VANTA idea against the current architecture.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running the unit test suite.")
    parser.add_argument(
        "--markdown-out",
        default=str(REPORTS_DIR / "vanta_idea_vs_architecture.md"),
        help="Where to write the Markdown report.",
    )
    parser.add_argument(
        "--json-out",
        default=str(REPORTS_DIR / "vanta_idea_vs_architecture.json"),
        help="Where to write the JSON report.",
    )
    args = parser.parse_args()

    REPORTS_DIR.mkdir(exist_ok=True)

    test_result = None if args.skip_tests else run_unit_tests()
    checks = build_checks()

    markdown = render_markdown(test_result, checks)
    markdown_path = Path(args.markdown_out)
    json_path = Path(args.json_out)

    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)

    markdown_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "repository": str(ROOT),
                "tests": test_result,
                "checks": [asdict(check) for check in checks],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Markdown report written to: {markdown_path}")
    print(f"JSON report written to: {json_path}")
    if test_result is not None:
        print(f"Test status: {'PASS' if test_result['passed'] else 'FAIL'}")

    return 0 if test_result is None or test_result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
