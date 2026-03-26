# OpenCTI Threat Intelligence Report Generator

Automated PDF threat intelligence report generator for **Telecom Operators and ISPs**, powered by [OpenCTI](https://github.com/OpenCTI-Platform/opencti) and **Claude AI**.

---

## Overview

This system automatically collects threat intelligence from OpenCTI and external feeds, generates AI-powered narrative analysis using Claude, and produces professional PDF reports on a scheduled basis. Designed specifically for telecom security teams.

```
OpenCTI GraphQL API ──┐
NVD / CISA KEV        ├──► Collectors ──► AI Narratives ──► PDF Reports ──► Web Dashboard
RIPE Stat BGP Feed    │    (Python)       (Claude API)       (ReportLab)     (Flask)
URLHaus / MalwareBazaar┘
```

---

## Reports Included (14 Total)

| Report | Schedule | Description |
|--------|----------|-------------|
| Executive Weekly Briefing | Weekly | C-suite summary of the week's threat landscape |
| BGP Hijacking Monitor | Daily | Route hijacking events and RPKI status |
| Telecom Vendor CVE Report | Weekly | Critical CVEs in Cisco, Nokia, Ericsson, Huawei, Juniper, etc. |
| SS7/Diameter/GTP Threats | Monthly | Signaling protocol attacks and SS7 firewall recommendations |
| APT Campaign Intelligence | Monthly | Nation-state APT groups targeting telecom (Salt Typhoon, Volt Typhoon, etc.) |
| IOC Watchlist | Daily | Fresh IOCs from OpenCTI + URLHaus + MalwareBazaar |
| DDoS Attack Intelligence | Weekly | Amplification vectors, volumetric attacks, mitigation architecture |
| Subscriber & Roaming Threats | Weekly | SIM swap fraud, IMSI catchers, OTP interception |
| 5G Security Threats | Monthly | SBA API abuse, O-RAN risks, network slicing isolation |
| Telecom Fraud Intelligence | Weekly | IRSF, SIM swap, Wangiri, PBX hacking, bypass fraud |
| Dark Web Monitoring | Weekly | Threat actor activity, credential dumps, access broker listings |
| Supply Chain Security | Monthly | Vendor risk (Huawei, ZTE, etc.), SBOM, firmware integrity |
| Regulatory Compliance | Monthly | GSMA FS.11/19/20/40, NIS2, GDPR, FCC CSRIC, ENISA |
| Monthly Executive Threat Profile | Monthly | Board-level monthly threat overview with investment priorities |

---

## Architecture

```
opencti-report-generator/
├── collectors/
│   ├── opencti_client.py       # GraphQL client for OpenCTI
│   └── external_feeds.py       # BGP, CVE, DDoS, SS7, URLHaus, MalwareBazaar
├── ai/
│   └── narrative_generator.py  # Claude AI narrative generation
├── formatters/
│   └── pdf_formatter.py        # ReportLab PDF formatter (branded)
├── generators/
│   ├── base_generator.py       # Abstract base class
│   ├── executive_briefing.py
│   ├── bgp_hijacking.py
│   ├── cve_report.py
│   ├── ss7_report.py
│   ├── apt_report.py
│   ├── ioc_watchlist.py
│   ├── ddos_report.py
│   ├── subscriber_report.py
│   ├── fiveg_report.py
│   ├── fraud_report.py
│   ├── dark_web_report.py
│   ├── supply_chain_report.py
│   ├── compliance_report.py
│   └── executive_profile.py
├── scheduler/
│   └── scheduler.py            # APScheduler (daily/weekly/monthly)
├── web/
│   ├── app.py                  # Flask dashboard
│   └── templates/index.html    # Dark-themed report UI
├── reports/                    # Generated PDFs stored here
├── test_dry_run.py             # 45/45 dry run tests (no real API)
├── requirements.txt
└── .env.example
```

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials:
# - OPENCTI_URL (e.g., http://localhost:8080)
# - OPENCTI_TOKEN (your OpenCTI API token)
# - ANTHROPIC_API_KEY (for AI narratives)
```

### 3. Run Dry Tests (No API Needed)

```bash
python3 test_dry_run.py
```

Output:
```
============================================================
Results: 45/45 tests passed
All tests passed!
============================================================
```

### 4. Generate All Reports Now

```bash
python3 scheduler/scheduler.py --run-now
```

### 5. Start the Web Dashboard

```bash
python3 web/app.py
# Open http://localhost:5050
```

### 6. Start the Scheduler

```bash
python3 scheduler/scheduler.py
```

Or via the web dashboard — click **Start Scheduler**.

---

## Web Dashboard

The Flask dashboard runs on `http://localhost:5050` and provides:

- **Report Generator panel** — click to generate any report on demand
- **Scheduler control** — start/stop the automatic schedule
- **Generated reports list** — download PDFs directly
- **Live job status** — next scheduled run times

---

## Report Schedule

| Frequency | Reports | Time (UTC) |
|-----------|---------|------------|
| Daily | BGP Hijacking, IOC Watchlist | 06:00 |
| Weekly (Monday) | Executive Briefing, CVE, DDoS, Subscriber, Fraud, Dark Web | 07:00 |
| Monthly (1st) | SS7, APT, 5G, Supply Chain, Compliance, Executive Profile | 08:00 |

---

## External Data Sources

| Source | Data | URL |
|--------|------|-----|
| OpenCTI | IOCs, threat actors, malware, campaigns | Your instance |
| NVD (NIST) | CVEs for telecom vendors | nvd.nist.gov |
| CISA KEV | Known exploited vulnerabilities | cisa.gov |
| RIPE Stat | BGP routing anomalies | stat.ripe.net |
| URLHaus | Malicious URLs | abuse.ch |
| MalwareBazaar | Malware samples | abuse.ch |

---

## Telecom-Specific Threat Coverage

- **BGP Hijacking** — prefix/sub-prefix hijacking, route leaks, BGPsec
- **SS7/Diameter** — location tracking, call interception, OTP hijacking, GTP tunneling
- **APT Groups** — Salt Typhoon, Volt Typhoon, APT28, Sandworm, Lazarus, LightBasin
- **5G Threats** — SBA API abuse, O-RAN xApp compromise, slice isolation bypass, MEC risks
- **Telecom Fraud** — IRSF, SIM swap, Wangiri, PBX hacking, bypass fraud, flash calls
- **DDoS** — Volumetric, reflection/amplification, GTP floods, signaling storms
- **Supply Chain** — Vendor risk (Huawei/ZTE), SBOM, firmware integrity
- **Compliance** — GSMA FS.11/19/20/40, NIS2, BEREC, FCC CSRIC, ENISA, GDPR

---

## AI-Powered Narratives

Each report includes AI-generated analysis using **Claude claude-sonnet-4-6**:
- Executive summaries tailored for C-suite readers
- Technical threat assessments for security engineers
- Prioritized, actionable recommendations
- Graceful fallback when API key is unavailable

---

## Corporate SSL (Zscaler)

If behind a corporate proxy with SSL inspection:

```bash
SSL_CERT_PATH=/path/to/combined-certs.pem
```

The combined cert should include your corporate CA + system CAs.

---

## Test Results

```
test_attack_patterns (SS7Collector) ... ok
test_roaming_risks (SS7Collector) ... ok
test_connection_failure_returns_false (OpenCTIClientOffline) ... ok
test_returns_list_on_network_error (CVECollectorOffline) ... ok
test_bullet_returns_list (PDFFormatter) ... ok
test_generate_creates_pdf (PDFFormatter) ... ok
test_h1_returns_list (PDFFormatter) ... ok
test_stat_boxes_returns_element (PDFFormatter) ... ok
test_table_returns_element (PDFFormatter) ... ok
test_generates_pdf (ExecutiveBriefing) ... ok
test_generates_pdf (BGPHijacking) ... ok
test_generates_pdf (CVEReport) ... ok
test_generates_pdf (SS7Report) ... ok
test_generates_pdf (APTReport) ... ok
test_generates_pdf (IOCWatchlist) ... ok
test_generates_pdf (DDoSReport) ... ok
test_generates_pdf (SubscriberReport) ... ok
test_generates_pdf (FiveGReport) ... ok
test_generates_pdf (FraudReport) ... ok
test_generates_pdf (DarkWebReport) ... ok
test_generates_pdf (SupplyChainReport) ... ok
test_generates_pdf (ComplianceReport) ... ok
test_generates_pdf (ExecutiveProfile) ... ok
test_scheduler_has_correct_job_count (Scheduler) ... ok
...
Results: 45/45 tests passed
```

---

## License

MIT
