# PhishScan — Static Phishing Email Analysis & DFIR Triage Toolkit

## Project Documentation

The complete project documentation, investigation workflow, practical analysis notes, and supporting materials are available in Notion.

**[View Full Project: Email Phishing Analysis](https://deluxe-rainbow-123.notion.site/Project-2-Email-Phishing-Analysis-3d756a08b0f8807c8535dae6e9d28d9b?source=copy_link)**



**PhishScan** is a Python-based, static-first phishing email analysis tool for SOC analysts, incident responders, DFIR learners, and security labs. It parses `.eml` messages, examines headers and authentication evidence, inspects message content and links, analyzes common attachment types, enriches indicators when explicitly enabled, and generates triage reports and hunting artifacts.

> **Safety model:** PhishScan does not directly visit extracted phishing URLs or execute attachments. Optional online enrichment makes requests to DNS/RDAP and configured threat-intelligence services. Read the privacy and safety notes before using `--online` or saving attachments.

## Features

- **Header analysis:** `From`, display name, `Reply-To`, `Return-Path`, `Message-ID`, mailer hints, recipient details, spam/gateway headers, and suspicious identity mismatches.
- **Mail routing:** Parses `Received` hops, extracts candidate IPs, examines timestamp anomalies, and checks HELO/reverse-DNS consistency when enough data is present.
- **Email authentication:** Parses SPF, DKIM, DMARC, ARC, and Microsoft composite authentication results from available headers; checks alignment where possible.
- **Body and social engineering:** Detects urgency, credential requests, financial requests, secrecy pressure, authority claims, extortion/callback language, generic greetings, hidden HTML, forms, tracking images, and link-text/destination mismatches.
- **URL triage:** Extracts and defangs indicators; identifies suspicious TLDs, lookalike domains, punycode, shorteners, abused hosting platforms, and certain URL-wrapping or redirect patterns.
- **Attachment triage:** Computes hashes and entropy, checks file signatures against extensions, and looks for suspicious patterns in common archives, LNKs, PDFs, HTML, SVG, Office documents, scripts, and executable-like files. Coverage depends on file type and optional tools.
- **Optional enrichment:** DNS TXT checks, RDAP/domain-age lookups, reverse DNS, optional local DKIM verification, VirusTotal lookups, and AbuseIPDB IP checks.
- **Investigation context:** Accepts flags for reported user interaction (clicked, credentials entered, MFA approved, attachment executed) and targeted roles.
- **Report artifacts:** Generates Markdown, HTML, JSON, IOC CSV, suggested KQL hunting queries, response recommendations, timeline details, MITRE ATT&CK mappings, and an analyst checklist.
- **Training fixture:** Can generate a synthetic phishing email for static-analysis practice.

## Requirements

- Python **3.8+**.
- Core email parsing and reporting use the Python standard library.
- Optional capabilities may use:
  - `oletools` for Office VBA/macro analysis.
  - `dnspython` or the system `dig` / `nslookup` commands for DNS lookups.
  - `dkimpy` for local DKIM verification.
  - `Pillow` and `pyzbar`, or `opencv-python` (plus `numpy` for the OpenCV path), for QR-code decoding.
  - `7z`, `7zz`, or `7za` for listing archive contents where supported.
  - `msgconvert` for converting Outlook `.msg` files before parsing.

Optional components can be absent; some checks will be skipped or less complete. Check the tool output and report for missing capabilities.

## Installation

Clone or download this repository, then enter the project directory:

```bash
git clone https://github.com/MrDreamReal/Eml-PhishScan-.git
cd Eml-PhishScan-
python3 --version
python3 phishscan.py --help
```

No mandatory third-party Python packages are required for the basic workflow. Install only the optional dependencies needed in your environment. For example:

```bash
python3 -m pip install oletools dnspython dkimpy pillow pyzbar
```

Alternatively, for QR decoding via OpenCV:

```bash
python3 -m pip install opencv-python numpy
```

`pyzbar` may also require the system ZBar library. Archive listing requires an appropriate `7z` executable. Install optional dependencies in a virtual environment where practical.

## Quick start

### Analyze one email

```bash
python3 phishscan.py suspicious.eml
```

By default, the tool writes reports to `phish_report/` and displays a console summary.

### Create a case-specific report

```bash
python3 phishscan.py suspicious.eml \
  --out cases/INC-2026-0142 \
  --case INC-2026-0142 \
  --analyst "SOC Analyst" \
  --reported-by "Helpdesk" \
  --status Open \
  --verbose
```

### Analyze multiple emails

```bash
python3 phishscan.py samples/*.eml \
  --out cases/batch-001 \
  --analyst "SOC Analyst" \
  --verbose
```

When multiple input files are supplied, a separate subdirectory is created for each input.

### Read from standard input

```bash
cat suspicious.eml | python3 phishscan.py - --out cases/stdin-case
```

### Create a synthetic training email

```bash
python3 phishscan.py --make-sample training_sample.eml
python3 phishscan.py training_sample.eml --out cases/training --verbose
```

The sample generator creates fake indicators and suspicious-looking content for parser testing. It is intended for static analysis. **Do not click links in generated samples, open attachments in a normal desktop session, or execute extracted content.**

## Command-line reference

Run `python3 phishscan.py --help` to see the arguments supported by your copy.

| Option | Description |
|---|---|
| `files` | One or more `.eml` files; use `-` to read from standard input. |
| `--out DIR` | Output directory. Default: `phish_report`. |
| `--format md,html,json` | Comma-separated report formats. Supported: `md`, `html`, and `json`. Default: all three. `iocs.csv` is also generated. |
| `--case ID` | Case or ticket ID. Otherwise, a timestamp-based ID is generated. |
| `--analyst NAME` | Analyst name recorded in the report. |
| `--reported-by NAME` | Person/team who reported the message. |
| `--status STATUS` | Case status text, such as `Open`, `Contained`, or `Closed`. |
| `--clicked` | Records that the user clicked a link; informs scoring and response recommendations. |
| `--creds` | Records that the user entered credentials. Treat as an analyst-supplied incident fact. |
| `--mfa` | Records that the user approved an MFA prompt. |
| `--executed` | Records that the attachment was opened or executed. |
| `--targeted` | Indicates the target is an executive, finance user, or administrator and influences severity. |
| `--online` | Enables DNS/RDAP/domain-age checks and available threat-intelligence lookups. Does not directly fetch the phishing URL. |
| `--vt-key KEY` | VirusTotal API key; alternatively use `VT_API_KEY`. |
| `--abuse-key KEY` | AbuseIPDB API key; alternatively use `ABUSEIPDB_API_KEY`. |
| `--save-attachments` | Saves attachments as SHA-256-named `.bin` files under the output directory's `attachments/` folder. Handle as potentially malicious evidence. |
| `--no-color` | Disables colored terminal output. |
| `-v`, `--verbose` | Prints more findings in the terminal. |
| `--make-sample FILE` | Generates a synthetic phishing `.eml` and exits. |

### Record a user-click event

Use `--clicked` only if the user interaction has been reported or confirmed:

```bash
python3 phishscan.py suspicious.eml \
  --case INC-2026-0142 --out cases/INC-2026-0142 --clicked
```

If credentials were submitted or an MFA prompt was approved, add `--creds` or `--mfa` respectively. If an attachment was executed, add `--executed`. These flags do not prove the event happened; they tell the report generator which incident scenario to consider.

## Output files

The output folder can contain:

- **`report.md`** — readable Markdown investigation report.
- **`report.html`** — report for viewing in a browser.
- **`report.json`** — structured findings, verdict, scores, IOCs, URLs, attachments, authentication details, and enrichment results.
- **`iocs.csv`** — extracted indicators of compromise with type and context.
- **`attachments/`** — created only when `--save-attachments` is enabled.
- Temporary working files may be used during archive listing and are removed by the relevant code path where possible.

The report includes available findings, an IOC list, potential MITRE ATT&CK mappings, suggested KQL hunting queries, recommendations, a checklist, and message headers. Exact contents depend on the sample and on optional tooling.

## Optional online enrichment

Use external enrichment only when permitted by your organization's data-handling policy.

Set API keys in your shell rather than hard-coding them in the script or committing them to Git:

```bash
export VT_API_KEY='YOUR_VIRUSTOTAL_API_KEY'
export ABUSEIPDB_API_KEY='YOUR_ABUSEIPDB_API_KEY'

python3 phishscan.py suspicious.eml --online --out cases/online-check

unset VT_API_KEY ABUSEIPDB_API_KEY
```

Without a VirusTotal key, VirusTotal lookups are skipped. Without an AbuseIPDB key, AbuseIPDB lookups are skipped. DNS and RDAP availability depends on network access and installed tools. The script can also perform a local DKIM check when `dkimpy` is installed and a DKIM signature exists.

### Privacy note for online mode

`--online` sends queries to external services. Depending on the extracted indicators and enabled APIs, this can disclose sender domains, IP addresses, attachment hashes, or suspicious URLs to third parties. VirusTotal URL lookups may disclose full URL indicators, including query strings. Do **not** submit confidential URLs, internal hostnames, private emails, live password-reset links, session identifiers, or other sensitive material to public services without approval. Prefer offline analysis for sensitive cases.

## How verdicts work

PhishScan combines heuristic findings into category scores and a triage verdict. The current scoring thresholds in the source are:

- **16 or more:** `MALICIOUS`
- **8–15:** `SUSPICIOUS`
- **3–7:** `LOW RISK / LIKELY SPAM`
- **Below 3:** `NO SIGNIFICANT INDICATORS`

Certain strong findings can escalate a verdict. Severity also depends on analyst-supplied interaction flags and whether the target is marked as targeted.

These are **tool-specific heuristic thresholds**, not a calibrated probability of compromise. Scores are not CVSS and do not replace investigation. False positives and false negatives are possible; validate high-impact findings against trusted gateway logs, identity logs, endpoint telemetry, and threat-intelligence evidence.

## Recommended SOC workflow

1. Preserve the original message and record its SHA-256 hash.
2. Run offline analysis first and review `report.md` / `report.html`.
3. Validate header anomalies and authentication results against the trusted receiving system. Some message headers can be forged or altered by forwarding.
4. Inspect extracted URLs and attachments through approved, isolated processes; do not click or execute suspicious content.
5. Enable online enrichment only when disclosure to external services is approved.
6. Correlate IOCs with email gateway, proxy/DNS, EDR, and identity logs.
7. Record confirmed actions, user interactions, and response outcomes in the case.
8. Use the generated containment checklist as a starting point, not as an automatic playbook.

## Safety, limitations, and responsible use

- PhishScan is a **static triage aid**, not a malware sandbox, a full email gateway, or a replacement for an experienced analyst.
- It does not directly browse to extracted URLs or execute attachments. Optional utilities may be invoked to inspect file structures, and optional online mode communicates with DNS/RDAP and threat-intelligence services.
- Parsing and detection depend on the available data and supported formats. Encrypted, malformed, password-protected, or unusual attachments may not be fully inspected.
- Keyword, domain, and pattern matching is heuristic. Legitimate email can contain suspicious-looking indicators, and sophisticated phishing may evade detection.
- `Received` headers and other fields may be missing, altered, or untrusted. Base routing conclusions on known trusted mail infrastructure.
- Saving attachments writes potentially dangerous evidence to disk. Store it in a controlled lab and never execute it on a production workstation.
- Reports can contain raw headers, email addresses, URLs, hashes, and other sensitive case data. Review and sanitize outputs before sharing or committing them.
- Use only on email and systems you are authorized to investigate, and comply with organizational policies and applicable law.

## Troubleshooting

- **No authentication results:** The email export may omit gateway-added headers. Obtain the original message with full headers or run approved online checks.
- **No QR decoding:** Install one supported QR stack (`Pillow` + `pyzbar`, or `opencv-python` + `numpy`) and required system dependencies.
- **Archive contents not listed:** Install a supported `7z`, `7zz`, or `7za` executable.
- **No online reputation results:** Verify network access and API key configuration, and check service limits. No result is not evidence of safety.
- **Outlook `.msg` input:** Convert to `.eml` with `msgconvert` where supported, or export the message as `.eml` from Outlook.
- **False positive or suspicious verdict:** Review the individual findings and validate them against independent evidence instead of relying on the score alone.

## Contributing

Bug reports, feature requests, test cases, and improvements are welcome. Please do not submit real victim emails, active credentials, session tokens, private URLs, or sensitive organization data. Use synthetic samples or sanitize evidence before sharing.

## License

No license is specified by the supplied source. Add a `LICENSE` file before distributing or accepting reuse of the project; do not assume that a public GitHub repository automatically grants permission to reuse the code.

---

**Disclaimer:** PhishScan is provided for defensive analysis, authorized incident response, and education. The analyst is responsible for validating findings and selecting appropriate response actions.
