[![Python CI](https://github.com/elliottkennedy52-ux/entra-rbac-auditor/actions/workflows/python-ci.yml/badge.svg)](https://github.com/elliottkennedy52-ux/entra-rbac-auditor/actions/workflows/python-ci.yml)

# Microsoft Entra ID & RBAC Policy Drift Auditor

Zero-dependency Python CLI policy-as-code auditor evaluating exported **Microsoft Entra ID** and **Azure RBAC** JSON snapshots for privilege creep, MFA gaps, stale external guests, and unenforced Conditional Access policies.

## Audit Rules
- **IAM-001 (CRITICAL):** Privileged RBAC/Entra role assigned without MFA registration
- **IAM-002 (HIGH):** External Guest user holding elevated administrative or write RBAC roles
- **IAM-003 (MEDIUM):** Stale enabled Guest account exceeding inactivity threshold (default: 90 days)
- **IAM-004 (HIGH):** Excessive active Global Administrator assignments (> 2 accounts)
- **IAM-005 (MEDIUM):** Conditional Access policy left in report-only or disabled state

## Quick Start
```bash
python3 entra_auditor.py -f samples/tenant_iam_export.json
python3 entra_auditor.py -f samples/tenant_iam_export.json --stale-days 60 -o report.json
```
