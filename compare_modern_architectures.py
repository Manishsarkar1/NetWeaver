#!/usr/bin/env python3
"""
Compare VANTA against modern real-world network security architectures.

This script does not browse the web at runtime. Instead, it uses:
1. Local repo inspection to infer VANTA's implemented capabilities.
2. A curated, source-backed model of current mainstream architectures.

Outputs:
- reports/vanta_vs_modern_architectures.md
- reports/vanta_vs_modern_architectures.json
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"


@dataclass
class ArchitectureProfile:
    name: str
    type: str
    strengths: list[str]
    weaknesses: list[str]
    scores: dict[str, int]
    source_notes: list[str]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def has_pattern(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.MULTILINE) is not None


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


def infer_vanta_profile() -> ArchitectureProfile:
    controller = read_text(ROOT / "ultimate_mtd_controller.py")
    attack = read_text(ROOT / "attack_simulator.py")
    benchmark = read_text(ROOT / "benchmark_suite.py")
    defense = read_text(ROOT / "vanta_core" / "defense.py")
    access = read_text(ROOT / "vanta_core" / "access_control.py")
    deployment = read_text(ROOT / "vanta_core" / "deployment.py")

    has_auth = all(
        has_pattern(controller, pattern)
        for pattern in [r"LoginManager", r"login_user", r"@login_required"]
    )
    has_dashboard = all(
        has_pattern(controller, pattern)
        for pattern in [r"SocketIO", r"@flask_app\.route\('/api/stats'", r"socketio\.emit"]
    )
    has_sdn = all(
        has_pattern(controller, pattern)
        for pattern in [r"ofproto_v1_3", r"class UltimateMTDController", r"real_to_virtual"]
    )
    has_threat_response = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (defense, r"class ThreatDetector"),
            (defense, r"detect_port_scan"),
            (controller, r"trigger='threat'|trigger=\"threat\""),
        ]
    )
    has_strategy_modes = all(
        has_pattern(defense, pattern)
        for pattern in [r"reply_triggered", r"time_based", r"packet_count_based", r"threat_triggered"]
    )
    has_tests = (ROOT / "tests" / "test_defense.py").exists()
    has_exports = all(
        has_pattern(controller, pattern)
        for pattern in [r"/api/export/csv", r"/api/export/json", r"/api/export/pdf"]
    )
    has_benchmarks = all(
        has_pattern(benchmark, pattern)
        for pattern in [r"def latency_benchmark", r"def throughput_benchmark", r"def strategy_comparison_benchmark"]
    )
    has_attack_suite = all(
        has_pattern(attack, pattern)
        for pattern in [r"def port_scan", r"def syn_flood", r"def ping_flood", r"def reconnaissance"]
    )
    has_identity_context = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (access, r"class ZeroTrustAccessPolicy"),
            (controller, r"mfa_code"),
            (controller, r"/api/access/context"),
        ]
    )
    has_device_context = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (access, r"device_trust"),
            (controller, r"X-VANTA-DEVICE-TRUST|device_trust"),
            (controller, r"device_id"),
        ]
    )
    has_mfa = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (access, r"verify_mfa"),
            (controller, r"mfa_verified"),
            (controller, r"VANTA_MFA_CODE"),
        ]
    )
    has_microsegmentation = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (access, r"segmentation_profile"),
            (access, r"admin-zone|user-zone|quarantine-zone"),
            (deployment, r"microsegmented-zones|policy-zones"),
        ]
    )
    has_remote_hybrid_model = all(
        has_pattern(text, pattern)
        for text, pattern in [
            (deployment, r"hybrid"),
            (controller, r"/api/deployment/profile"),
            (controller, r"/api/health"),
        ]
    )
    has_operational_tests = (ROOT / "tests" / "test_access_control.py").exists()

    scores = {
        "dynamic_network_obfuscation": 5 if has_sdn and has_threat_response else 2,
        "identity_centric_access": 4 if has_identity_context and has_mfa else 2 if has_identity_context else 0,
        "device_posture_awareness": 3 if has_device_context else 0,
        "lateral_movement_containment": 4 if has_threat_response and has_microsegmentation else 3 if has_threat_response else 1,
        "granularity_of_control": 4 if has_strategy_modes and has_microsegmentation else 2,
        "real_time_visibility": 4 if has_dashboard and has_exports else 2,
        "benchmarking_and_measurement": 4 if has_benchmarks and has_tests else 2,
        "hybrid_enterprise_fit": 3 if has_remote_hybrid_model and has_device_context else 1 if has_remote_hybrid_model else 0,
        "deployment_maturity": 4 if has_tests and has_operational_tests and has_exports and has_attack_suite and has_remote_hybrid_model else 2 if has_tests and has_exports else 1,
    }

    strengths = []
    weaknesses = []

    if has_sdn:
        strengths.append("Implements SDN-driven VIP virtualization and morphing rather than static addressing.")
    if has_threat_response:
        strengths.append("Can react to reconnaissance by triggering morph events in near real time.")
    if has_strategy_modes:
        strengths.append("Supports multiple morphing strategies instead of a single fixed defense policy.")
    if has_dashboard:
        strengths.append("Includes a live dashboard and API endpoints for visibility and demoability.")
    if has_benchmarks:
        strengths.append("Has local attack and benchmark tooling to evaluate the prototype.")
    if has_identity_context and has_mfa:
        strengths.append("Adds MFA-aware, identity-centric access decisions for control-plane operations.")
    if has_device_context:
        strengths.append("Evaluates device trust and exposes posture-aware access context for demo and policy use.")
    if has_remote_hybrid_model:
        strengths.append("Includes deployment profiles and health endpoints that make hybrid-ready operation clearer.")

    if not has_microsegmentation:
        weaknesses.append("Does not implement workload-level microsegmentation or policy labels common in modern enterprise segmentation.")
    if not has_device_context:
        weaknesses.append("Does not evaluate device health or posture before allowing access.")
    if not has_mfa:
        weaknesses.append("Authentication is basic login/session handling, not strong identity-centric zero trust.")
    if not has_remote_hybrid_model:
        weaknesses.append("Architecture is aimed at Mininet/OVS lab environments rather than hybrid enterprise deployment.")
    if not has_tests or not has_exports or not has_operational_tests:
        weaknesses.append("Operational maturity is still prototype-level rather than production-grade.")

    return ArchitectureProfile(
        name="VANTA",
        type="Research prototype",
        strengths=strengths,
        weaknesses=weaknesses,
        scores=scores,
        source_notes=[
            "Local repo inspection of ultimate_mtd_controller.py, vanta_core/defense.py, attack_simulator.py, benchmark_suite.py, and tests.",
        ],
    )


def modern_profiles() -> list[ArchitectureProfile]:
    return [
        ArchitectureProfile(
            name="Traditional perimeter / static network",
            type="Legacy baseline",
            strengths=[
                "Simple to understand and operate in stable on-prem environments.",
                "Often lower initial deployment complexity than more adaptive architectures.",
            ],
            weaknesses=[
                "Relies heavily on trusted internal network assumptions.",
                "Weaker against lateral movement and stale reconnaissance problems.",
                "Less aligned with remote, hybrid, and cloud-first environments.",
            ],
            scores={
                "dynamic_network_obfuscation": 0,
                "identity_centric_access": 1,
                "device_posture_awareness": 0,
                "lateral_movement_containment": 1,
                "granularity_of_control": 1,
                "real_time_visibility": 2,
                "benchmarking_and_measurement": 2,
                "hybrid_enterprise_fit": 1,
                "deployment_maturity": 5,
            },
            source_notes=[
                "NIST SP 800-207 says zero trust shifts from static, network-based perimeters to protecting users, assets, and resources.",
                "Source: https://csrc.nist.gov/pubs/sp/800/207/final",
            ],
        ),
        ArchitectureProfile(
            name="Zero Trust Architecture (general)",
            type="Mainstream modern architecture",
            strengths=[
                "Assumes breach and verifies each request instead of trusting network location.",
                "Strong fit for remote, cloud, and hybrid access patterns.",
                "Emphasizes identity, device, policy, analytics, and least privilege.",
            ],
            weaknesses=[
                "Can be complex to design and integrate across many enterprise pillars.",
                "Does not by itself obfuscate network reconnaissance the way MTD can.",
            ],
            scores={
                "dynamic_network_obfuscation": 1,
                "identity_centric_access": 5,
                "device_posture_awareness": 5,
                "lateral_movement_containment": 4,
                "granularity_of_control": 5,
                "real_time_visibility": 4,
                "benchmarking_and_measurement": 4,
                "hybrid_enterprise_fit": 5,
                "deployment_maturity": 5,
            },
            source_notes=[
                "NIST SP 800-207 defines zero trust as moving defenses away from static network perimeters and focusing on users, assets, and resources.",
                "CISA Zero Trust Maturity Model v2.0 describes five pillars and cross-cutting capabilities for modern deployment.",
                "Sources: https://csrc.nist.gov/pubs/sp/800/207/final ; https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model",
            ],
        ),
        ArchitectureProfile(
            name="Zero Trust microsegmentation",
            type="Modern containment architecture",
            strengths=[
                "Reduces attack surface and limits lateral movement through fine-grained segmentation.",
                "Works well across hybrid, multi-cloud, and data-center environments.",
                "Improves visibility and containment around east-west traffic.",
            ],
            weaknesses=[
                "Can be operationally heavy to plan, label, and maintain at scale.",
                "Focused more on containment and policy than on deception or address obfuscation.",
            ],
            scores={
                "dynamic_network_obfuscation": 1,
                "identity_centric_access": 4,
                "device_posture_awareness": 3,
                "lateral_movement_containment": 5,
                "granularity_of_control": 5,
                "real_time_visibility": 4,
                "benchmarking_and_measurement": 4,
                "hybrid_enterprise_fit": 5,
                "deployment_maturity": 5,
            },
            source_notes=[
                "CISA says microsegmentation is a critical component of ZTA that reduces attack surface, limits lateral movement, and enhances visibility.",
                "Illumio describes modern segmentation as hybrid and workload-level, focused on preventing spread across environments.",
                "Sources: https://www.cisa.gov/resources-tools/resources/microsegmentation-zero-trust-part-one-introduction-and-planning ; https://www.illumio.com/illumio-segmentation",
            ],
        ),
        ArchitectureProfile(
            name="BeyondCorp-style zero trust access",
            type="Identity/device-aware access model",
            strengths=[
                "Moves access control away from the network perimeter toward user and device context.",
                "Strong support for access from untrusted networks without traditional VPN assumptions.",
                "Well aligned with modern remote workforce models.",
            ],
            weaknesses=[
                "Primarily focused on secure access decisions, not on network deception.",
                "Less directly focused on internal topology mutation than VANTA.",
            ],
            scores={
                "dynamic_network_obfuscation": 0,
                "identity_centric_access": 5,
                "device_posture_awareness": 5,
                "lateral_movement_containment": 3,
                "granularity_of_control": 4,
                "real_time_visibility": 4,
                "benchmarking_and_measurement": 3,
                "hybrid_enterprise_fit": 5,
                "deployment_maturity": 5,
            },
            source_notes=[
                "Google says BeyondCorp grants access based on contextual factors from the user and device rather than network location.",
                "Source: https://cloud.google.com/beyondcorp?hl=en",
            ],
        ),
    ]


def compare_profiles(vanta: ArchitectureProfile, others: list[ArchitectureProfile]) -> list[dict]:
    criteria = list(vanta.scores.keys())
    comparisons = []

    for other in others:
        wins = []
        losses = []
        ties = []
        for criterion in criteria:
            v_score = vanta.scores[criterion]
            o_score = other.scores[criterion]
            if v_score > o_score:
                wins.append(criterion)
            elif v_score < o_score:
                losses.append(criterion)
            else:
                ties.append(criterion)

        comparisons.append(
            {
                "architecture": other.name,
                "vanta_total": sum(vanta.scores.values()),
                "other_total": sum(other.scores.values()),
                "wins": wins,
                "losses": losses,
                "ties": ties,
            }
        )

    return comparisons


def criterion_label(key: str) -> str:
    return key.replace("_", " ").title()


def render_markdown(test_result: dict, vanta: ArchitectureProfile, others: list[ArchitectureProfile], comparisons: list[dict]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# VANTA vs Modern Security Architectures",
        "",
        f"- Generated: {generated}",
        f"- Repository: `{ROOT}`",
        "- Scope: compares VANTA to current mainstream security architecture patterns, not just to your internal project docs.",
        "",
        "## Test Result",
        f"- Command: `{test_result['command']}`",
        f"- Status: {'PASS' if test_result['passed'] else 'FAIL'}",
    ]

    if test_result["stdout"]:
        lines.extend(["", "```text", test_result["stdout"], "```"])

    lines.extend(
        [
            "",
            "## What This Comparison Means",
            "- `5` means very strong alignment with that criterion.",
            "- `0` means the architecture essentially does not address that criterion.",
            "- This is a qualitative architecture comparison, not a benchmark-backed product ranking.",
            "",
            "## Criteria",
        ]
    )

    for key in vanta.scores:
        lines.append(f"- {criterion_label(key)}")

    lines.extend(["", "## Score Matrix", ""])

    headers = ["Architecture"] + [criterion_label(key) for key in vanta.scores] + ["Total"]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")

    all_profiles = [vanta] + others
    for profile in all_profiles:
        row = [profile.name] + [str(profile.scores[key]) for key in vanta.scores] + [str(sum(profile.scores.values()))]
        lines.append("| " + " | ".join(row) + " |")

    lines.extend(["", "## VANTA Assessment", ""])
    lines.append("### Strengths")
    for item in vanta.strengths:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("### Weaknesses")
    for item in vanta.weaknesses:
        lines.append(f"- {item}")

    lines.extend(["", "## Head-to-Head Summary", ""])
    for entry in comparisons:
        lines.append(f"### VANTA vs {entry['architecture']}")
        lines.append(f"- Total score: VANTA {entry['vanta_total']} vs {entry['other_total']}")
        if entry["wins"]:
            lines.append("- VANTA leads in: " + ", ".join(criterion_label(item) for item in entry["wins"]))
        if entry["losses"]:
            lines.append("- VANTA trails in: " + ", ".join(criterion_label(item) for item in entry["losses"]))
        if entry["ties"]:
            lines.append("- Ties in: " + ", ".join(criterion_label(item) for item in entry["ties"]))
        lines.append("")

    lines.extend(["## Takeaways"])
    lines.append("- VANTA is strongest as a moving-target-defense and deception-oriented research architecture.")
    lines.append("- VANTA is more adaptive than traditional static network architecture for reconnaissance invalidation.")
    lines.append("- Modern zero trust and microsegmentation architectures are stronger for enterprise identity, device context, least privilege, and hybrid deployment.")
    lines.append("- VANTA would become more globally competitive if combined with zero trust identity/device controls and finer-grained segmentation.")

    lines.extend(["", "## Source Notes"])
    seen_sources = []
    for profile in others:
        for note in profile.source_notes:
            if note not in seen_sources:
                seen_sources.append(note)
                lines.append(f"- {note}")

    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare VANTA against modern security architectures.")
    parser.add_argument(
        "--markdown-out",
        default=str(REPORTS_DIR / "vanta_vs_modern_architectures.md"),
        help="Where to write the Markdown report.",
    )
    parser.add_argument(
        "--json-out",
        default=str(REPORTS_DIR / "vanta_vs_modern_architectures.json"),
        help="Where to write the JSON report.",
    )
    args = parser.parse_args()

    REPORTS_DIR.mkdir(exist_ok=True)

    test_result = run_unit_tests()
    vanta = infer_vanta_profile()
    others = modern_profiles()
    comparisons = compare_profiles(vanta, others)
    markdown = render_markdown(test_result, vanta, others, comparisons)

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
                "vanta": asdict(vanta),
                "comparisons": comparisons,
                "modern_architectures": [asdict(profile) for profile in others],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"Markdown report written to: {markdown_path}")
    print(f"JSON report written to: {json_path}")
    print(f"Test status: {'PASS' if test_result['passed'] else 'FAIL'}")
    return 0 if test_result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
