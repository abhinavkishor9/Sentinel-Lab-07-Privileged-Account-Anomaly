# Timeline

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

