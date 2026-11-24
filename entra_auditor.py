#!/usr/bin/env python3
"""
Entra ID & RBAC Policy Drift Auditor
Evaluates exported Microsoft Entra ID user/role/Conditional Access JSON snapshots
for over-privileged Global Admins, MFA gaps, stale guest accounts, and report-only CA policies.
"""

import argparse
import json
from pathlib import Path

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Intune Administrator",
    "Owner",
    "Contributor",
}


def audit_iam_snapshot(snapshot: dict, stale_days: int = 90) -> dict:
    users = snapshot.get("users", [])
    ca_policies = snapshot.get("conditional_access_policies", [])

    findings: list[dict] = []
    global_admins: list[str] = []
    score = 100

    for user in users:
        upn = user.get("upn", "unknown")
        enabled = user.get("account_enabled", False)
        mfa = user.get("mfa_registered", False)
        user_type = user.get("user_type", "Member")
        inactive_days = user.get("days_since_last_signin", 0)
        roles = set(user.get("roles", []))

        if not enabled:
            continue

        if "Global Administrator" in roles:
            global_admins.append(upn)

        priv_held = sorted(roles.intersection(PRIVILEGED_ROLES))

        if priv_held and not mfa:
            findings.append({
                "severity": "CRITICAL",
                "rule": "IAM-001",
                "target": upn,
                "detail": f"Privileged account ({', '.join(priv_held)}) lacks MFA registration.",
            })
            score -= 25

        if user_type == "Guest" and priv_held:
            findings.append({
                "severity": "HIGH",
                "rule": "IAM-002",
                "target": upn,
                "detail": f"External Guest holds elevated RBAC role(s): {', '.join(priv_held)}.",
            })
            score -= 20

        if user_type == "Guest" and inactive_days >= stale_days:
            findings.append({
                "severity": "MEDIUM",
                "rule": "IAM-003",
                "target": upn,
                "detail": f"Stale enabled Guest account inactive for {inactive_days} days (>= {stale_days}d).",
            })
            score -= 10

    if len(global_admins) > 2:
        findings.append({
            "severity": "HIGH",
            "rule": "IAM-004",
            "target": "Tenant-Wide",
            "detail": f"Excessive Global Administrators detected ({len(global_admins)} active; recommended <= 2).",
        })
        score -= 15

    for policy in ca_policies:
        if policy.get("state") != "enabled":
            findings.append({
                "severity": "MEDIUM",
                "rule": "IAM-005",
                "target": policy.get("name", "Unnamed Policy"),
                "detail": f"Conditional Access policy is not enforced (state={policy.get('state')}).",
            })
            score -= 10

    final_score = max(0, score)
    grade = (
        "A" if final_score >= 90 else
        "B" if final_score >= 80 else
        "C" if final_score >= 70 else
        "D" if final_score >= 60 else "F"
    )

    return {
        "tenant": snapshot.get("tenant_name", "Unknown Tenant"),
        "users_evaluated": len(users),
        "active_global_admins": len(global_admins),
        "compliance_score": f"{final_score}/100",
        "grade": grade,
        "total_findings": len(findings),
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit Microsoft Entra ID & RBAC JSON exports for IAM policy drift."
    )
    parser.add_argument(
        "-f", "--file",
        default="samples/tenant_iam_export.json",
        help="Path to Entra ID / RBAC JSON export (default: samples/tenant_iam_export.json)",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        help="Inactivity threshold in days for flagging stale guest accounts (default: 90)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output path to save JSON compliance report",
    )
    args = parser.parse_args()

    snapshot = json.loads(Path(args.file).read_text(encoding="utf-8"))
    report = audit_iam_snapshot(snapshot, stale_days=args.stale_days)

    print(json.dumps(report, indent=2))
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] Compliance report saved to {args.output}")


if __name__ == "__main__":
    main()
