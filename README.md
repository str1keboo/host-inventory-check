# host-inventory-check

Checks whether hosts are enrolled in **SentinelOne**, **Wazuh**, and **Rapid7 InsightVM**, and reports coverage gaps.

Answers "is this server actually covered by our EDR, SIEM, and VM tooling?" across hundreds of assets without clicking through three consoles.

## How it works

Input is a headerless CSV: `hostname,ip`. Either field may be blank.

For each host, in each enabled console:

1. Match by **hostname** first.
2. If no hostname match, fall back to **IP**.
3. If only one field is supplied, only that lookup runs.

Output is a CSV plus a console summary listing hosts missing from one or more consoles, and a `MatchedBy` column so you can spot assets that only matched by IP — usually a rename or a stale record.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- API access to whichever consoles you want to query

## Setup

```powershell
git clone https://github.com/str1keboo/host-inventory-check.git
cd host-inventory-check
```

Open `Check-Hosts.ps1` and edit the **CONFIG** region at the top — console URLs, Rapid7 region, Wazuh mode. No credentials go in this file.

Store credentials using either a vault or environment variables:

```powershell
# Option A - SecretManagement vault (recommended)
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore      -Scope CurrentUser
Register-SecretVault -Name SOCVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault

Set-Secret -Name S1ApiToken    -Secret 'xxx'
Set-Secret -Name R7ApiKey      -Secret 'xxx'
Set-Secret -Name WazuhUser     -Secret 'xxx'
Set-Secret -Name WazuhPassword -Secret 'xxx'
```

```powershell
# Option B - environment variables
[Environment]::SetEnvironmentVariable('S1_API_TOKEN','xxx','User')
[Environment]::SetEnvironmentVariable('R7_API_KEY','xxx','User')
[Environment]::SetEnvironmentVariable('WAZUH_USER','xxx','User')
[Environment]::SetEnvironmentVariable('WAZUH_PASSWORD','xxx','User')
```

If neither is configured, the script prompts interactively and stores nothing.

## Usage

Create `hosts.csv` — no header row. See [`hosts.example.csv`](hosts.example.csv):

```csv
web01.example.local,10.0.0.10
db01.example.local,10.0.0.11
app01,10.0.0.12
appliance01,
,10.0.0.20
```

Then:

```powershell
.\Check-Hosts.ps1
```

Results are written to `host-inventory-check-results.csv`.

You can disable any console you don't use:

```powershell
$EnableSentinelOne = $true
$EnableWazuh       = $false
$EnableRapid7      = $true
```

Disabled consoles are skipped entirely — no credential prompt, and they aren't counted as coverage gaps.

## Console notes

### SentinelOne

Standard v2.1 API, `Authorization: ApiToken <token>`. Hostname lookups use `computerName__like` (partial match); IP lookups use `networkInterfaceInet__contains`.

### Rapid7 InsightVM

Insight Platform (cloud) API, `X-Api-Key` header. Set your region code in CONFIG — `us`, `us2`, `us3`, `eu`, `ca`, `au`, `ap`, `aps2`, `me1`.

Rapid7's query field names vary between API versions. If searches return nothing, build the equivalent filter in **Assets → Filtered Search** in the UI and copy the exact field name it generates.

### Wazuh

Two modes, set via `$WazuhMode`.

**`direct`** — self-managed manager. Authenticates against `https://<manager>:55000` with username/password exchanged for a JWT, as per Wazuh's documented Server API. Set `$AllowSelfSignedWazuh = $true` if your manager uses a self-signed certificate (PS7+ only, and it relaxes validation for Wazuh requests only).

**`dashboard`** — Wazuh Cloud. Port 55000 is not exposed externally, so the script reaches the Server API through the dashboard plugin proxy, the same path the built-in Dev Tools console uses:

1. `POST /auth/login` → dashboard session cookie
2. `POST /api/login` with `{ idHost: "1" }` → sets `wz-token` / `wz-user` / `wz-api` cookies
3. `POST /api/request` with `{ method, path, body, id }`

Step 3 must send **only** the `osd-xsrf` header. The plugin reads the manager token from the cookies set in step 2 — adding an `Authorization: Bearer` header overrides that and returns `401 Authentication Exception`.

`idHost` is the registry ID from **Server management → API Connections** (the `ID` column, typically `1`), *not* the cluster name. The script auto-discovers it via `/hosts/apis`.

> **These dashboard plugin routes are internal to Wazuh and undocumented.** They can change between versions. Fine for on-demand checks; for scheduled automation, ask Wazuh Cloud support to expose the Server API to an allow-listed IP with a dedicated API user, then switch to `direct` mode.

## Known limitations

- Wazuh hostname lookups use `q=name=` (exact match). Agents registered under an FQDN won't match a short hostname — a `search=` partial-match fallback is on the roadmap.
- Link-local IPv6 addresses in the input will never match anything.
- Network appliances that can't host agents will always report as gaps. Expected.

## Security

- No credentials in the repo. Add a `.gitignore` covering `*.csv` (except `hosts.example.csv`), `.env`, and any local config before your first real run.
- Use per-user credentials rather than a shared token, so console audit logs stay attributable.
- Prefer read-only API accounts. The Wazuh dashboard login is a user account and carries that user's full UI permissions.
- Certificate validation is enabled by default for all consoles.
- Results CSVs contain internal hostnames and IPs — treat them as internal-only.

## License

MIT — see [LICENSE](LICENSE).
