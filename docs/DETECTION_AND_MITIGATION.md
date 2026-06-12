# Detection & Mitigation — Defending against Device-Code Token Abuse

This is the **blue-team companion** to the [TokenAbuse-Azure write-up](../WRITEUP.md). For each
stage of the attack chain it answers two questions: *how do I see it?* and *how do I stop it?*

---

## 1. Defence summary

| Attack stage | Detection | Prevention |
|--------------|-----------|------------|
| Device-code request | Sign-in logs: `authenticationProtocol = deviceCode` | Conditional Access policy blocking/scoping the flow |
| Victim completes sign-in | Device-code grant from new/unmanaged device or atypical location | Phishing-resistant MFA; user awareness |
| Token capture & reuse | Access from impossible-travel locations, new IP/ASN | Sign-in risk policies; short token lifetime |
| FOCI pivot | Refresh-token redemptions across multiple first-party client IDs | Continuous Access Evaluation (CAE); token revocation |
| Graph / SharePoint enumeration | Spike in `MicrosoftGraphActivityLogs`; mass file reads | Least-privilege site permissions; sensitivity labels |
| Exfiltration | Bulk `downloadUrl` retrievals; DLP signals | Defender for Cloud Apps file policies; DLP |

---

## 2. Block the device-code flow (the single most effective control)

Most organisations never legitimately need the device-code flow. A Conditional Access policy can
shut the whole technique down:

> **Entra ID → Protection → Conditional Access → New policy**
> - **Users:** All users (exclude break-glass accounts)
> - **Target resources:** All cloud apps
> - **Conditions → Authentication flows:** *Device code flow* = **Selected**
> - **Grant:** **Block access**

If some teams genuinely need it (e.g. CLI tooling), scope the policy to allow it **only** for those
users from **compliant/managed devices**, and block it everywhere else.

---

## 3. Hunting queries (Microsoft Sentinel / Log Analytics — KQL)

**Detect device-code sign-ins:**

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, DeviceDetail
| order by TimeGenerated desc
```

**Device-code sign-in followed quickly by access from a different IP (token theft pattern):**

```kql
let codeSignins = SigninLogs
    | where AuthenticationProtocol == "deviceCode"
    | project codeTime = TimeGenerated, UserPrincipalName, codeIP = IPAddress;
SigninLogs
| where AuthenticationProtocol != "deviceCode"
| join kind=inner codeSignins on UserPrincipalName
| where TimeGenerated between (codeTime .. (codeTime + 1h))
| where IPAddress != codeIP
| project UserPrincipalName, codeTime, codeIP, laterTime = TimeGenerated, laterIP = IPAddress, AppDisplayName
```

**FOCI pivot — one user, many first-party client IDs in a short window:**

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize clients = make_set(AppDisplayName), appCount = dcount(AppId) by UserPrincipalName, bin(TimeGenerated, 1h)
| where appCount >= 4
| order by appCount desc
```

**Mass file access via Graph (collection/exfiltration):**

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestUri has_any ("/drive", "/drives", "/sites")
| summarize requests = count(), uris = make_set(RequestUri, 20) by UserId, IPAddress, bin(TimeGenerated, 10m)
| where requests > 50
| order by requests desc
```

---

## 4. Harden tokens & identity

- **Continuous Access Evaluation (CAE):** enable it so revoked sessions and risky sign-ins are cut
  off in near-real-time instead of waiting for token expiry.
- **Sign-in & user risk policies (Identity Protection):** require MFA or block on medium/high risk.
- **Token lifetime:** keep refresh-token lifetimes short; revoke on user-risk events.
- **Phishing-resistant MFA:** FIDO2 / passkeys / Windows Hello — and pair with *number matching* so
  users can't blindly approve a push that an attacker triggered.
- **Revoke on suspicion:** `Revoke-MgUserSignInSession` (Graph PowerShell) invalidates all refresh
  tokens for a compromised user immediately.

```powershell
# Emergency containment — kill all sessions for a compromised user
Connect-MgGraph -Scopes "User.RevokeSessions.All"
Revoke-MgUserSignInSession -UserId "victim@contoso.com"
```

---

## 5. Fix the second flaw — SharePoint over-permissioning

The token only mattered because the victim could read a sensitive library. Independently of the
phishing issue:

- Audit site and library permissions; remove "Everyone" / "All Company" from sensitive sites.
- Apply **sensitivity labels** and **DLP policies** to confidential documents.
- Use **Defender for Cloud Apps** file policies to alert on or block bulk downloads.
- Run periodic **access reviews** so excessive standing access is caught and removed.

---

## 6. User-awareness angle

The decisive moment is a human typing a code. Train users on one simple rule:

> **Never enter a device code you didn't generate yourself on your own device.**
> Microsoft will never email you a code to "keep your access" — that prompt should only ever appear
> on a device *you* are actively signing into (a TV, a CLI, a console).

---

## References

- [Microsoft — Conditional Access: authentication flows](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)
- [Microsoft — Continuous Access Evaluation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Microsoft — Investigate risk with Identity Protection](https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-investigate-risk)
- [Microsoft Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
