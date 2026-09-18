# Timeline — Sentinel Lab 07

## Investigation Timeline

| Time UTC | Activity | Result |
|---|---|---|
| 08:30 | Privileged account authentication | Success from Hyderabad |
| 22:15 | Authentication attempt | Failed from `203.0.113.50` |
| 22:16 | Authentication attempt | Failed from `203.0.113.50` |
| 22:17 | Authentication attempt | Success from `203.0.113.50` / New York |
| 22:20 | Authentication attempt | Success from `203.0.113.50` / New York |
| 22:22 | PowerShell execution | `Get-LocalGroupMember Administrators` |
| 22:25 | PowerShell execution | `Get-Service` |
| 22:30 | Identity and endpoint correlation | 5-minute authentication-to-endpoint gap identified |
| 22:35 | Evidence assessment | Suspicious privileged-account sequence identified |
| 22:40 | Evidence gaps reviewed | Additional telemetry required |
| 22:45 | Final verdict assigned | Suspicious — Privileged Account Anomaly |

---

## Key Event Sequence

    08:30 UTC
    admin@sentinellab.local
    Successful authentication
    10.10.10.50
    Hyderabad
    DESKTOP-ADMIN01

    ↓

    22:15 UTC
    Failed authentication
    203.0.113.50
    New York

    ↓

    22:16 UTC
    Failed authentication
    203.0.113.50
    New York

    ↓

    22:17 UTC
    Successful authentication
    203.0.113.50
    New York
    DESKTOP-ADMIN01

    ↓ 5 minutes

    22:22 UTC
    admin
    DESKTOP-ADMIN01
    explorer.exe → powershell.exe
    Get-LocalGroupMember Administrators

    ↓ 3 minutes

    22:25 UTC
    admin
    DESKTOP-ADMIN01
    explorer.exe → powershell.exe
    Get-Service

---

## Investigation Milestones

### Baseline Established

A successful privileged authentication was observed from Hyderabad at 08:30 UTC.

### Authentication Anomaly

Two failed authentication attempts occurred from `203.0.113.50` in New York.

### Authentication Success

The same source successfully authenticated at 22:17 UTC.

### Location Change

The privileged account showed successful authentication from both Hyderabad and New York.

### Endpoint Activity

Five minutes after the successful New York authentication, administrative PowerShell activity was observed on `DESKTOP-ADMIN01`.

### Process Analysis

The primary PowerShell event was:

    explorer.exe → powershell.exe

with:

    Get-LocalGroupMember Administrators

### Secondary Activity

Three minutes later, the same account executed:

    Get-Service

### Cross-Source Correlation

The successful authentication and endpoint activity share the same account and computer context.

### Evidence Assessment

The sequence was classified as suspicious, but unauthorized access and compromise remained unconfirmed.

---

## Evidence Summary

| Evidence | Status |
|---|---|
| Privileged account | Confirmed |
| Two failed authentications | Confirmed |
| Same source later succeeded | Confirmed |
| New York successful authentication | Confirmed |
| Hyderabad successful authentication | Confirmed |
| PowerShell execution | Confirmed |
| Administrative group query | Confirmed |
| Five-minute authentication-to-endpoint gap | Confirmed |
| Unauthorized authentication | Unknown |
| Malicious PowerShell activity | Unknown |
| Account compromise | Unknown |
| System impact | Unknown |

---

## Final Assessment

**Verdict:** Suspicious — Privileged Account Anomaly

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Primary Evidence Chain:**

    Failed authentication
    →
    Successful privileged authentication
    →
    New York
    →
    5 minutes
    →
    explorer.exe → powershell.exe
    →
    Get-LocalGroupMember Administrators

**Evidence Gap:**

No MFA, Conditional Access, sign-in risk, authentication method, PowerShell Script Block, network, file, child-process, account-change, or endpoint-security telemetry was available.

**Final SOC Principle:**

> **Treat privileged-account anomalies as investigation leads and validate the complete timeline before concluding compromise.**
