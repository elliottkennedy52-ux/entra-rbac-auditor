[![Python CI](https://github.com/elliottkennedy52-ux/entra-rbac-auditor/actions/workflows/python-ci.yml/badge.svg)](https://github.com/elliottkennedy52-ux/entra-rbac-auditor/actions/workflows/python-ci.yml)

# Microsoft Entra ID & RBAC Policy Drift Auditor

A zero-dependency Python CLI policy-as-code auditor that evaluates exported **Microsoft Entra ID (Azure AD)** and **Azure RBAC** JSON snapshots for privilege creep, MFA registration gaps, stale external guest accounts, and unenforced Conditional Access policies.

## Audit Rules & Security Checks

| Rule ID | Severity | Check Description |
| :--- | :--- | :--- |
| **IAM-001** | `CRITICAL` | Privileged RBAC/Entra ID role assigned to an active account without MFA registration |
| **IAM-002** | `HIGH` | External `Guest` user holding elevated administrative or write RBAC permissions |
| **IAM-003** | `MEDIUM` | Stale enabled `Guest` account exceeding inactivity threshold (default: 90 days) |
| **IAM-004** | `HIGH` | Excessive active `Global Administrator` assignments (> 2 accounts) |
| **IAM-005** | `MEDIUM` | Conditional Access policy left in `report-only` or `disabled` state |

## Quick Start

```bash
# Run against the included sample tenant export
python3 entra_auditor.py -f samples/tenant_iam_export.json

# Export a JSON compliance report with a custom 60-day guest inactivity threshold
python3 entra_auditor.py -f samples/tenant_iam_export.json --stale-days 60 -o report.json
```
