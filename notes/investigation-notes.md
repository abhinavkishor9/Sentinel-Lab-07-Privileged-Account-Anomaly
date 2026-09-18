# Investigation Notes — Sentinel Lab 07

## Investigation Overview

**Investigation Type:** Privileged Account Anomaly  
**Platform:** Microsoft Sentinel  
**Data Source:** Synthetic KQL `datatable()`  
**Primary Account:** `admin@sentinellab.local`  
**Primary Host:** `DESKTOP-ADMIN01`

---

## Investigation Question

Does the authentication and subsequent administrative activity associated with the privileged account represent suspicious behavior requiring further investigation?

---

## Evidence Reviewed

The investigation reviewed:

- Privileged account authentication events.
- Failed authentication attempts.
- Successful authentication events.
- Source IP addresses.
- Authentication locations.
- Associated computer.
- PowerShell execution.
- Parent process.
- Administrative command line.
- Time relationship between authentication and endpoint activity.

---

## Authentication Review

The privileged account showed the following activity:

| Time UTC | IP Address | Result | Location |
|---|---|---|---|
| 08:30 | `10.10.10.50` | Success | Hyderabad |
| 22:15 | `203.0.113.50` | Failed | New York |
| 22:16 | `203.0.113.50` | Failed | New York |
| 22:17 | `203.0.113.50` | Success | New York |
| 22:20 | `203.0.113.50` | Success | New York |

The initial successful authentication provides the baseline.

The later sequence from `203.0.113.50` is the main authentication anomaly.

---

## Failed Authentication Analysis

The failed authentication query returned:

| IP Address | Location | Failed Attempts |
|---|---|---:|
| `203.0.113.50` | New York | 2 |

The two failures occurred immediately before successful authentication from the same source.

This is suspicious authentication behavior, but the available evidence does not establish the source as malicious.

---

## Successful Authentication Analysis

The source `203.0.113.50` produced:

    22:15 — Failed
    22:16 — Failed
    22:17 — Success
    22:20 — Success

The successful authentication after repeated failures became the main identity-side finding.

---

## Location Analysis

The successful sign-ins were associated with:

    Hyderabad
    New York

Source IPs:

    10.10.10.50
    203.0.113.50

The account therefore showed successful authentication from two locations.

This was treated as an anomaly rather than proof of compromise.

---

## Endpoint Analysis

The privileged account later generated two PowerShell events:

| Time UTC | Parent Process | Process | Command |
|---|---|---|---|
| 22:22 | `explorer.exe` | `powershell.exe` | `Get-LocalGroupMember Administrators` |
| 22:25 | `explorer.exe` | `powershell.exe` | `Get-Service` |

The 22:22 event was selected as the primary endpoint finding because it followed shortly after the successful authentication.

---

## Primary Endpoint Event

Observed context:

| Field | Value |
|---|---|
| Time | 2026-09-17 22:22 UTC |
| User | `admin` |
| Computer | `DESKTOP-ADMIN01` |
| Parent Process | `explorer.exe` |
| Process | `powershell.exe` |
| Command | `Get-LocalGroupMember Administrators` |

The command queries members of the local Administrators group.

The activity is administrative in nature, but the available data does not establish whether it was authorized.

---

## Identity-to-Endpoint Correlation

The relevant successful authentication occurred at:

**22:17 UTC**

The administrative PowerShell event occurred at:

**22:22 UTC**

Time difference:

**5 minutes**

Both events involve:

    admin
    DESKTOP-ADMIN01

This provides a meaningful correlation between the authentication and endpoint events.

---

## Complete Event Sequence

    08:30
    Successful authentication
    10.10.10.50
    Hyderabad

    ↓

    22:15
    Failed authentication
    203.0.113.50
    New York

    ↓

    22:16
    Failed authentication
    203.0.113.50
    New York

    ↓

    22:17
    Successful authentication
    203.0.113.50
    New York

    ↓ 5 minutes

    22:22
    admin
    DESKTOP-ADMIN01
    explorer.exe → powershell.exe
    Get-LocalGroupMember Administrators

    ↓ 3 minutes

    22:25
    admin
    DESKTOP-ADMIN01
    explorer.exe → powershell.exe
    Get-Service

---

## Evidence Classification

### Confirmed

- The account is identified as privileged.
- Two failed authentication attempts occurred from `203.0.113.50`.
- The same source later authenticated successfully.
- Successful authentication occurred from New York.
- The account also had successful authentication from Hyderabad.
- PowerShell executed on `DESKTOP-ADMIN01`.
- `admin` was the associated endpoint user.
- `Get-LocalGroupMember Administrators` was executed.
- The endpoint activity occurred five minutes after the 22:17 successful authentication.

### Plausible

- The authentication and endpoint activity may be related.
- The sequence may represent unauthorized privileged-account activity.
- The administrative PowerShell activity may have followed the successful authentication.

### Unknown

- Whether the authentication was unauthorized.
- Whether the source IP was controlled by an attacker.
- Whether the privileged account was compromised.
- Whether the PowerShell activity was malicious.
- Whether system or account changes occurred.
- Whether the activity resulted in further impact.

---

## Investigation Verdict

**Suspicious — Privileged Account Anomaly**

The sequence warrants additional investigation, but the available evidence is insufficient to confirm compromise.

---

## Recommended Follow-Up

A deeper investigation should review:

1. MFA and Conditional Access results.
2. Authentication method and sign-in risk.
3. Device identity and compliance.
4. Privileged role membership.
5. PowerShell Script Block Logging.
6. Process creation and child processes.
7. Group and account changes.
8. Network connections.
9. Endpoint security alerts.
10. User confirmation of the authentication.

---

## Key Lesson

The strongest finding came from correlating:

**Privileged account + failed authentication + successful authentication + location change + endpoint activity**

Each event was investigated in context rather than treated as standalone proof of compromise.
