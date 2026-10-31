# Vulnerability and patch management (TASK-030)

SentinelAI reports known vulnerabilities in installed programs and in the Windows release, using signed vulnerability
data from the provider. Core evaluates the data on the central computer, so no evaluation needs the Internet, and every
result comes from fixed product and version rules, never from a language model. Nothing is patched or installed by
this feature.

Owner decisions of 2026-10-31 (`.agent/DECISIONS.md`):

- **Source.** The provider builds the data from public sources: the NIST National Vulnerability Database (CVE, CVSS,
  affected versions) and the CISA Known Exploited Vulnerabilities catalog. The provider signs it with the update key.
- **Delivery.** Core downloads newer data from the provider's update server while **checking for updates** is on
  (Settings → Updates, off by default). An administrator can also import the signed file in Settings → Vulnerability data.
- **Coverage.** The provider curates a list of common business programs plus Windows client releases. A program is
  assessed only when it matches one listed product exactly. Anything else stays explicitly unassessed.

## What Core reports

For each enrolled computer, Desktop → Devices → a computer → **Vulnerabilities** shows:

- **Findings.** For each finding: CVE, CVSS severity and score, whether it is known to be exploited (with the date CISA
  added it), the program and installed version, the fixed version, and the remediation. Findings are ordered with known
  exploited ones first, then by severity.
- **Coverage.** Every program in the computer's software list gets exactly one state:
  - **covered**: one listed product matched by name, publisher and version form; its findings, possibly none, are reliable;
  - **ambiguous**: more than one listed product matched, or the name matched but the publisher differs or is missing;
    no vulnerability is claimed;
  - **unsupportedVersion**: one product matched but the version is missing or not in that product's form; no
    vulnerability is claimed;
  - **notCovered**: no listed product describes it.

  Windows is assessed only for an exact release, display version and build, with the update revision (UBR). Server
  releases are not covered yet because their product names include the edition.
- **Freshness.** The data's version, build time, age and sources are shown in Settings and with every assessment.
  Data older than 14 days is marked stale. Vulnerabilities published after the data was built are missing.

## Alerts and Risk

At each endpoint telemetry report (hourly), Core evaluates the computer's programs and its latest inventory's Windows
release against the data in use. Findings become tracked alerts with fixed policy:

| Rule ID | Condition | Alert severity |
| --- | --- | --- |
| SA-VULN-001 | At least one known exploited vulnerability (CISA KEV) | critical |
| SA-VULN-002 | At least one other vulnerability with a critical CVSS base score | high |
| SA-VULN-003 | At least one other vulnerability with a high CVSS base score | medium |

Medium, low and unscored vulnerabilities raise no alert; they are listed with the computer. Each alert's evidence names
the data version and up to ten findings. Risk scores these alerts as endpoint telemetry detections, which are confirmed
by the computer's latest telemetry report. New data takes effect for alerts at each computer's next report, and for the
Vulnerabilities view immediately.

## Data format and trust

- The data is one JSON file, `sentinelai-vulnerability-feed-v1` (`rules/Vulnerabilities/VulnerabilityFeed.cs`). It
  holds the sources with their retrieval times, the curated products with their matching rules, the vulnerabilities
  with affected version ranges, and counts of what was left out. Its version derives from the build time
  (`year.monthday.hourminute`, for example `2026.1031.1405`).
- It is signed as the update artifact `sentinelai-vulnerability-feed` with the same development update key and channel
  as the release. Every Core build carries `update-trust.json` (key ID, channel, public key; public data only).
- Core accepts data only when all of these hold:
  - the manifest verifies with that trust;
  - it names the vulnerability artifact;
  - the file matches the signed size and SHA-256;
  - the file's version equals the manifest's;
  - it is newer than the data in use, so older data is never restored.

  The data is kept in Core's SQLite database and survives restarts.
- Routes:
  - `GET /api/admin/vulnerabilities`: status, freshness and sources;
  - `POST /api/admin/vulnerabilities/feed` with `manifest` and `feed` in base64: answers 200 imported, 409 not newer,
    422 not signed for this installation or not intact, 503 when the build has no trust;
  - `GET /api/admin/devices/{id}/vulnerabilities`: one computer's assessment.
- From the update server Core requests only two addresses, without redirects:
  - `<URL>/vulnerability-feed.manifest.json`;
  - `<URL>/vulnerability-feed/<version>/vulnerability-feed.json`.

## Building and publishing the data (provider)

The curated product list is `tools/vulnerability-feed/products.json`. Each application entry has the NVD CPE vendor
and product, an anchored display-name pattern, its publishers and a version pattern whose first group is the comparable
version. Each Windows entry has the release name, display version and build.

1. **Download the inputs.**
   - NVD CVE API 2.0 pages for each listed CPE into one folder, for example
     `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:7-zip:7-zip`. Respect the NVD rate
     limits; an API key raises them.
   - The CISA KEV catalog JSON:
     `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
2. **Build the data.** The same inputs and times always give the same bytes:

   ```text
   dotnet run --project tools/update-dev -- feed-build --products tools/vulnerability-feed/products.json --nvd <folder>
     --kev <kev.json> --nvd-retrieved <UTC> --kev-retrieved <UTC> --generated <UTC> --output vulnerability-feed.json
   ```

   The builder leaves out what it cannot map reliably and counts it, together with the reasons:
   - configurations that also need another vulnerable product, and negated or nested conditions;
   - CPEs for another update, edition or target platform;
   - affected versions without bounds.

   A program combined with a platform condition applies when that condition names Windows, alone or among other
   platforms ("on Windows or macOS"). A configuration limited to other platforms (for example macOS only) does not apply
   to Windows and is left out without being counted.
3. **Sign** it with the update key, the version the file states and the server address:

   ```text
   dotnet run --project tools/update-dev -- sign --private-key <key> --key-id <dev-…> --package vulnerability-feed.json
     --version <feed version> --artifact-id sentinelai-vulnerability-feed
     --artifact-url <URL>/vulnerability-feed/<version>/vulnerability-feed.json --channel <channel> --output vulnerability-feed.manifest.json
   ```

4. **Publish** both files at those two addresses, or give them to the administrator to import.

## Limits

- Only machine-wide programs from the uninstall registry are assessed. The Agent does not report per-user and Store
  apps. When the software list was cut short, the view says so.
- Coverage is limited to the curated list. A wrong pattern or CPE leads to a program being not covered or ambiguous,
  never to a claimed vulnerability.
- Data is as fresh as its last build. No patch is applied; remediation is guidance for an administrator.
