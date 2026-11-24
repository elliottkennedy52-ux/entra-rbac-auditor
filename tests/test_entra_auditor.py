import json
from pathlib import Path

from entra_auditor import audit_iam_snapshot


def test_sample_snapshot_flags_expected_drift():
    snapshot = json.loads(Path("samples/tenant_iam_export.json").read_text(encoding="utf-8"))
    report = audit_iam_snapshot(snapshot, stale_days=90)

    assert report["users_evaluated"] == 5
    assert report["active_global_admins"] == 2
    assert report["total_findings"] == 5
    assert report["grade"] == "F"

    rules_triggered = {f["rule"] for f in report["findings"]}
    assert rules_triggered == {"IAM-001", "IAM-002", "IAM-003", "IAM-005"}


def test_hardened_tenant_scores_grade_a():
    clean_snapshot = {
        "tenant_name": "Hardened Corp",
        "conditional_access_policies": [
            {"name": "CA01-Require-MFA", "state": "enabled"},
        ],
        "users": [
            {
                "upn": "secadmin@hardened.com",
                "user_type": "Member",
                "account_enabled": True,
                "mfa_registered": True,
                "days_since_last_signin": 1,
                "roles": ["Global Administrator"],
            }
        ],
    }
    report = audit_iam_snapshot(clean_snapshot)
    assert report["compliance_score"] == "100/100"
    assert report["grade"] == "A"
    assert report["total_findings"] == 0
