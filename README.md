<div align="center">

# PhishGuard

**AI-Based Phishing Website Detection and Risk Analysis System Using Machine Learning**

Paste a URL and get a 0-100 risk score you can trace back to its causes. Four machine-learning models read the URL itself, and 50+ live security checks look at the website behind it.

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-REST%20API-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![scikit-learn 1.9](https://img.shields.io/badge/scikit--learn-1.9-F7931E?logo=scikitlearn&logoColor=white)](https://scikit-learn.org/)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite 8](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Live demo on Vercel](https://img.shields.io/badge/Live%20demo-Vercel-000000?logo=vercel&logoColor=white)](https://phishguard-mini-project.vercel.app)

[**Live demo**](https://phishguard-mini-project.vercel.app) · [Demo video](#demo-video) · [Screenshots](#screenshots) · [Architecture](docs/ARCHITECTURE.md) · [Viva demo guide](docs/DEMO_GUIDE.md) · [API docs](https://phishguard-mini-project.vercel.app/docs)

<img src="docs/media/demo.gif" alt="PhishGuard demo: a deep scan of a phishing URL, the report tabs, analytics and the Model Lab" width="100%">

</div>

> **B.Tech mini project.** Ayushi Tiwari, under the guidance of Mr. Vishal Gupta. Department of Computer Science & Engineering, Lloyd Institute of Engineering & Technology, Greater Noida. Dr. A.P.J. Abdul Kalam Technical University (AKTU), Lucknow.

**Live demo: <https://phishguard-mini-project.vercel.app>**

> [!NOTE]
> The hosted version runs in **demo mode**. It starts from a bundled snapshot of demo data, so your scans, reports and watchlist items **are reset** whenever the serverless function restarts. Nothing runs in the background there: watchlist checks run once a day through a **daily Vercel Cron job**. A banner in the dashboard reminds you of this. For the full experience, run it locally (see [Getting started](#getting-started)).

## Table of contents

- [About the project](#about-the-project)
- [Features](#features)
- [Demo video](#demo-video)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Machine learning](#machine-learning)
- [Risk scoring](#risk-scoring)
- [Tech stack](#tech-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Load the Chrome extension](#load-the-chrome-extension)
- [Deploying to Vercel](#deploying-to-vercel)
- [API reference](#api-reference)
- [Usage guide](#usage-guide)
- [Testing and verification](#testing-and-verification)
- [Limitations and ethical use](#limitations-and-ethical-use)
- [Future scope](#future-scope)
- [Credits](#credits)

## About the project

### Problem statement

Phishing sites copy real websites to steal usernames, passwords and payment details. They can look almost identical to the genuine site, and checking a URL by hand takes technical knowledge most users do not have. Blacklists help, but a phishing site created this morning is usually not on any list yet.

PhishGuard tackles this by learning what phishing URLs look like. It extracts features from the URL, scores them with trained machine-learning models, and combines the result with live checks of the website (domain age, certificate, redirects, login forms, brand look-alikes, threat-intelligence feeds). Every URL is classified as **Legitimate**, **Suspicious** or **Phishing**, with a risk score and the reasons behind it.

### Objectives

These are condensed from the project synopsis:

1. Build a machine-learning system that detects phishing websites by analysing their URLs and related characteristics.
2. Collect and prepare a reliable labelled dataset of legitimate and phishing URLs.
3. Extract meaningful URL features (length, sub-domains, special characters, suspicious keywords and similar patterns) and pre-process them for classification.
4. Train and compare **Logistic Regression, Decision Tree, Random Forest and Support Vector Machine**, and select the most suitable model.
5. Classify each URL as Legitimate, Suspicious or Phishing and give a clear risk indication.
6. Provide a simple, interactive interface where users can enter a URL and see its security status.

### How it works

The synopsis workflow, as implemented:

```mermaid
flowchart LR
    A["URL Input<br/>web, email/SMS text, QR,<br/>bulk, API, extension"] --> B["Validation<br/>scheme, host, normalisation"]
    B --> C["Feature Extraction<br/>44 lexical URL features"]
    C --> D["Pre-processing<br/>same normalisation and<br/>feature order as training"]
    D --> E["ML Model<br/>Random Forest (best of 4)"]
    E --> F["Risk Classification<br/>60% ML + 40% live checks,<br/>blocklists, community"]
    F --> G["Result<br/>verdict, 0-100 risk,<br/>trust tier, explanations"]
```

The synopsis planned a Streamlit page. The final build has a React dashboard and a FastAPI REST API instead, so the same engine serves the web UI, the browser extension, bulk jobs and scripts.

## Features

### Detection and machine learning

- **Four classifiers** (Logistic Regression, Decision Tree, Random Forest, SVM) trained on 44 lexical URL features. The best model by test F1 (currently Random Forest) drives the score, and all four probabilities are shown side by side.
- **Explainable predictions.** Each report lists the features that pushed the phishing probability up or down, with their signed impact.
- **Model Lab page** with the dataset composition, the model comparison table, ROC and precision-recall curves, confusion matrices, feature importance, per-class feature averages, the "with scheme / without scheme" comparison and the realistic held-out evaluation.

### Deep URL analysis

- **50+ checks in 7 categories**: lexical (URL), domain, network, SSL/TLS, HTTP and page content, brand, and reputation. Each check has a status (pass, warn, fail, info or error) and a weight.
- **WHOIS**: registrar, creation and expiry dates, privacy, with an **RDAP fallback** when the `whois` command is not available.
- **DNS**: A, AAAA, MX, NS and TXT records, plus MX and SPF/DMARC checks. **IP geolocation, ASN and hosting provider** (ip-api.com with ipwho.is as fallback).
- **SSL/TLS certificate**: issuer, validity window, days left, certificate age, SANs, protocol and self-signed detection.
- **HTTP probe**: redirect chain, status, response time, server, security headers, technologies, forms (password fields, off-site form actions), links, iframes, external scripts, meta refresh and suspicious JavaScript patterns.
- **Brand impersonation** for 92 brands, detected through typosquatting, homoglyphs, combosquatting, brand-as-subdomain, punycode, path and page-content techniques.
- **Page content**: category (16 classes, such as banking, payment, login, crypto and parked), language with a translate link, parked-domain detection and tracker IDs (Google Analytics, GTM, Facebook Pixel, ...).
- **Page resources and HTML source**: every script, stylesheet, image, frame and form the page references, the contacted domains (first or third party), and the stored HTML of the final page (gzipped, up to 500 KB) with line numbers and search.
- **Optional page screenshot** through the thum.io screenshot service. It is off by default and can be turned on in Settings.
- **SSRF guard**: before any connection to a scanned site, the host is resolved and every address must be public. This is checked again on every redirect hop. Private, loopback, link-local and reserved addresses are refused, and only ports 80, 443, 8080 and 8443 are allowed.

### Threat intelligence

- **Local threat feeds**: OpenPhish, PhishTank, URLhaus, Phishing.Database and Phishing Army (about 657,000 entries in the current snapshot), with search, top targeted brands and top TLDs.
- **Multi-engine verdict**: every feed, five DNS blocklist zones (Spamhaus DBL and ZEN, SURBL, URIBL, SpamCop) and the PhishGuard ML engine count as engines, and the report shows "N of M engines flagged".
- **Optional Google Safe Browsing and VirusTotal lookups** if you add your own API keys in Settings.
- **Tranco popularity rank**, used as a strong "safe" signal for well-known sites.
- **Typosquat finder**: dnstwist-style permutations of a domain with 13 techniques (omission, insertion, repetition, transposition, replacement, homoglyph, bitsquatting, vowel swap, hyphenation, addition, sub-domain, TLD swap and dictionary), checked in DNS to see which ones resolve.
- **Relationship graph**: scanned domains linked through shared IPs, ASNs, name servers, registrars, countries, impersonated brands and redirects, plus "similar scans" on the same IP, ASN or registrar.

### Monitoring and alerts

- **Watchlist**: re-check URLs or domains at an interval (1 minute to 7 days), optionally watch for newly resolving look-alike domains, and see the check history of each item.
- **Alerts** for high-risk scans, verdict changes on watched items, new resolving typosquats, bulk-job results and community verification, with a bell menu in the header.
- **Activity log**: an audit trail of scans, rescans, deletions, reports, votes, bulk jobs, watchlist and settings changes, feed refreshes and exports. Each event is linked to its scan or domain, which feeds the per-scan **Timeline** tab.

### Community reporting

- **PhishTank-style reports.** Anyone can report a URL as phishing or legitimate, and others vote. The reporter's label counts as the first vote. A report is **verified** at a net +3 phishing votes and **rejected** at -3. A verified report raises the URL's risk to at least 85.

### Analytics and tracking

- **Overview dashboard** with KPIs (including the average trust score), scans over time, the verdict split, the risk-score histogram, top impersonated brands, top hosting countries, recent alerts, model health and a live feed of recent scans that refreshes every 5 seconds.
- **Analytics page** for any range (24h, 7d, 30d, 90d or all): scans and average risk over time, a weekday-by-hour heatmap, TLDs, scan sources, impersonation techniques, SSL status, domain age, top failing checks, countries, top domains, threat types, reputation tiers, content categories, a detection funnel, throughput and check error rates.
- **History** with search, filters, sorting and CSV/JSON export. CSV cells are protected against spreadsheet formula injection. IP, ASN, registrar, category, threat type and tier values are clickable pivot filters.
- **Domain page** with every scan of a domain and its risk trend, and **compare** for any two scans of the same domain.

### REST API

- A documented **REST API** under `/api` (JSON, ISO-8601 UTC timestamps) with interactive **Swagger UI at `/docs`** and ReDoc at `/redoc`. The **API Guide** page has copy-paste examples.
- **Bulk scanning** of up to 500 URLs per job (JSON list or CSV/TXT upload), processed in the background, 5 at a time.
- **URL extraction** from email or SMS text, including defanged links such as `hxxp://evil[.]com`. QR codes are decoded in the browser.

### Browser extension

- A **Chrome extension** (Manifest V3, plain JavaScript, no build step). It scans the current tab, shows the risk score as a coloured badge, warns with a desktop notification and an optional in-page banner, and adds a "Scan link with PhishGuard" item to the right-click menu. See [`extension/README.md`](extension/README.md).

### Feature parity

The design merges user-facing features of 12 public URL-safety services, researched in [`docs/FEATURES.md`](docs/FEATURES.md). The table lists only what PhishGuard actually implements, and where each idea comes from.

| Capability in PhishGuard | Inspired by |
|---|---|
| URL scan with verdict and 0-100 risk score | All 12 tools |
| ML classifier with per-feature explanations | urlscan.io (ML verdicts), IPQualityScore, CheckPhish |
| Local threat-feed lookups, feed search and statistics | PhishTank, OpenPhish |
| "N of M engines flagged" with per-engine results | VirusTotal, URLVoid, Sucuri SiteCheck |
| DNS blocklists (Spamhaus, SURBL, URIBL, SpamCop) | Cisco Talos, Sucuri SiteCheck |
| Optional Google Safe Browsing / VirusTotal lookups (own API key) | Google Safe Browsing, VirusTotal |
| Redirect chain, HTTP and security headers, technologies | VirusTotal, urlscan.io, Sucuri SiteCheck, IPQualityScore |
| Login/password-form and off-site form detection | VirusTotal, urlscan.io |
| Suspicious JavaScript and iframes | Sucuri SiteCheck, VirusTotal |
| SSL/TLS certificate details | All 12 tools |
| WHOIS, domain age, registrar, privacy | URLVoid, ScamAdviser, IPQualityScore |
| DNS records, IP geolocation, ASN, hosting | VirusTotal, URLVoid, urlscan.io, Cisco Talos |
| Brand impersonation (92 brands, 7 techniques) | urlscan.io, CheckPhish, OpenPhish |
| Typosquat / look-alike domain finder | CheckPhish |
| Watchlist monitoring with alerts | CheckPhish, urlscan.io Pro |
| Community reports and voting | PhishTank, VirusTotal |
| Trust score with positive and negative factors | ScamAdviser |
| Reputation tiers, Trusted to Untrusted | Cisco Talos, Norton Safe Web |
| Threat type: social engineering, malware, unwanted software | Google Safe Browsing |
| Content category, language, parked-domain detection | Cisco Talos, IPQualityScore |
| Popularity rank (Tranco) | ScamAdviser, Norton Safe Web |
| Plain-English summary of the result | urlscan.io |
| HTML source viewer, page resources, contacted domains, tracker IDs | urlscan.io, VirusTotal, CheckPhish |
| Optional page screenshot | urlscan.io, VirusTotal, CheckPhish |
| Relationship graph and pivot search | VirusTotal Graph, urlscan.io |
| Scan history, filters, export, compare, per-domain timeline | urlscan.io, VirusTotal |
| Bulk scanning | URLVoid, IPQualityScore, VirusTotal |
| URLs from email/SMS text (plus QR codes) | CheckPhish (Outlook add-in) |
| Browser extension | Norton Safe Web, ScamAdviser, IPQualityScore, CheckPhish |
| REST API with OpenAPI docs | All 12 tools |
| Global statistics and a live scan feed | OpenPhish, Cisco Talos, PhishTank, urlscan.io |

## Demo video

<video src="https://github.com/at9501264-stack/mini-project/raw/main/docs/media/demo.mp4" controls width="100%"></video>

If the player does not load, open the video directly: [docs/media/demo.mp4](docs/media/demo.mp4). The walkthrough (about 80 s) shows the Overview, a deep scan of a phishing-style URL, the report tabs, Analytics, the Model Lab, the relationship graph and History. The GIF at the top of this page is its first part.

## Screenshots

The images below were captured with [`scripts/capture_media.py`](scripts/capture_media.py), which opens every page in a headless browser. Click any image for the full-size version.

<!-- MEDIA-GALLERY:START -->
<!-- screenshot gallery for docs/media (scripts/capture_media.py --readme can regenerate it) -->

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/overview.png"><img src="docs/media/overview.png" alt="Overview: KPI cards, scans over time, verdict split, risk histogram and the live scan feed"></a><br><sub>Overview: KPI cards, scans over time, verdict split, risk histogram and the live scan feed</sub></td>
    <td width="50%" valign="top"><a href="docs/media/scan.png"><img src="docs/media/scan.png" alt="Scan page: single URL, email/SMS text (URL extraction) or QR code, with an optional deep scan"></a><br><sub>Scan page: single URL, email/SMS text (URL extraction) or QR code, with an optional deep scan</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-summary.png"><img src="docs/media/report-phishing-summary.png" alt="Report summary: risk gauge, trust tier, plain-English summary, factors and every check"></a><br><sub>Report summary: risk gauge, trust tier, plain-English summary, factors and every check</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-ml.png"><img src="docs/media/report-phishing-ml.png" alt="ML Explanation: the four model probabilities and the features that raised or lowered the score"></a><br><sub>ML Explanation: the four model probabilities and the features that raised or lowered the score</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-reputation.png"><img src="docs/media/report-phishing-reputation.png" alt="Reputation tab: detection engines (feeds, DNS blocklists, PhishGuard ML) and community votes"></a><br><sub>Reputation tab: detection engines (feeds, DNS blocklists, PhishGuard ML) and community votes</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-graph.png"><img src="docs/media/report-phishing-graph.png" alt="Graph tab: relationship graph around the scanned domain"></a><br><sub>Graph tab: relationship graph around the scanned domain</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/analytics-1.png"><img src="docs/media/analytics-1.png" alt="Analytics (1/6): Scans over time, Average risk trend, Activity heatmap"></a><br><sub>Analytics (1/6): Scans over time, Average risk trend, Activity heatmap</sub></td>
    <td width="50%" valign="top"><a href="docs/media/model-lab-1.png"><img src="docs/media/model-lab-1.png" alt="Model Lab: dataset, model comparison and live model statistics"></a><br><sub>Model Lab: dataset, model comparison and live model statistics</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/graph.png"><img src="docs/media/graph.png" alt="Relationship graph: domains linked through shared IPs, ASNs, name servers, registrars, brands and redirects"></a><br><sub>Relationship graph: domains linked through shared IPs, ASNs, name servers, registrars, brands and redirects</sub></td>
    <td width="50%" valign="top"><a href="docs/media/history.png"><img src="docs/media/history.png" alt="History: search, filters, pivots and CSV/JSON export of every scan"></a><br><sub>History: search, filters, pivots and CSV/JSON export of every scan</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/typosquat.png"><img src="docs/media/typosquat.png" alt="Typosquat finder: look-alike permutations of paypal.com and which of them resolve"></a><br><sub>Typosquat finder: look-alike permutations of paypal.com and which of them resolve</sub></td>
    <td width="50%" valign="top"><a href="docs/media/watchlist.png"><img src="docs/media/watchlist.png" alt="Watchlist: scheduled re-checks of URLs/domains with typosquat monitoring"></a><br><sub>Watchlist: scheduled re-checks of URLs/domains with typosquat monitoring</sub></td>
  </tr>
</table>

<details>
<summary><b>All other screenshots (32)</b></summary>


#### Scanning

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/bulk.png"><img src="docs/media/bulk.png" alt="Bulk scan: paste or upload up to 500 URLs and follow the job"></a><br><sub>Bulk scan: paste or upload up to 500 URLs and follow the job</sub></td>
  </tr>
</table>

#### Scan report

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-legit-ml.png"><img src="docs/media/report-legit-ml.png" alt="ML Explanation for a legitimate site"></a><br><sub>ML Explanation for a legitimate site</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-legit-summary.png"><img src="docs/media/report-legit-summary.png" alt="Report of a legitimate site (google.com): low risk, Favorable tier"></a><br><sub>Report of a legitimate site (google.com): low risk, Favorable tier</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-brand.png"><img src="docs/media/report-phishing-brand.png" alt="Brand tab: impersonated brand, technique and similarity"></a><br><sub>Brand tab: impersonated brand, technique and similarity</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-content.png"><img src="docs/media/report-phishing-content.png" alt="Content tab: page category, language, parked-domain check and tracker IDs"></a><br><sub>Content tab: page category, language, parked-domain check and tracker IDs</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-domain.png"><img src="docs/media/report-phishing-domain.png" alt="Domain tab: WHOIS (registrar, age, expiry) and DNS records"></a><br><sub>Domain tab: WHOIS (registrar, age, expiry) and DNS records</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-geo.png"><img src="docs/media/report-phishing-geo.png" alt="Geo &amp; Hosting tab: IP geolocation, ASN and hosting provider"></a><br><sub>Geo &amp; Hosting tab: IP geolocation, ASN and hosting provider</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-http.png"><img src="docs/media/report-phishing-http.png" alt="HTTP tab: redirect chain, security headers, forms, links and scripts"></a><br><sub>HTTP tab: redirect chain, security headers, forms, links and scripts</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-resources.png"><img src="docs/media/report-phishing-resources.png" alt="Resources tab: contacted domains and every script, style, image, frame and form"></a><br><sub>Resources tab: contacted domains and every script, style, image, frame and form</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-source.png"><img src="docs/media/report-phishing-source.png" alt="Source tab: stored HTML of the page with line numbers and search"></a><br><sub>Source tab: stored HTML of the page with line numbers and search</sub></td>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-ssl.png"><img src="docs/media/report-phishing-ssl.png" alt="SSL tab: certificate issuer, validity window, SANs and protocol"></a><br><sub>SSL tab: certificate issuer, validity window, SANs and protocol</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/report-phishing-timeline.png"><img src="docs/media/report-phishing-timeline.png" alt="Timeline tab: events recorded for this scan and its domain"></a><br><sub>Timeline tab: events recorded for this scan and its domain</sub></td>
  </tr>
</table>

#### Analytics

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/analytics-2.png"><img src="docs/media/analytics-2.png" alt="Analytics (2/6): Activity heatmap, Top-level domains, Scan sources, Impersonation techniques"></a><br><sub>Analytics (2/6): Activity heatmap, Top-level domains, Scan sources, Impersonation techniques</sub></td>
    <td width="50%" valign="top"><a href="docs/media/analytics-3.png"><img src="docs/media/analytics-3.png" alt="Analytics (3/6): SSL status, Domain age distribution, Top failed checks, Countries, Top domains"></a><br><sub>Analytics (3/6): SSL status, Domain age distribution, Top failed checks, Countries, Top domains</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/analytics-4.png"><img src="docs/media/analytics-4.png" alt="Analytics (4/6): Countries, Top domains, Threat insights, Threat types, Reputation tiers"></a><br><sub>Analytics (4/6): Countries, Top domains, Threat insights, Threat types, Reputation tiers</sub></td>
    <td width="50%" valign="top"><a href="docs/media/analytics-5.png"><img src="docs/media/analytics-5.png" alt="Analytics (5/6): Threat types, Reputation tiers, Content categories, Detection funnel, Performance"></a><br><sub>Analytics (5/6): Threat types, Reputation tiers, Content categories, Detection funnel, Performance</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/analytics-6.png"><img src="docs/media/analytics-6.png" alt="Analytics (6/6): Detection funnel, Performance, Throughput, Check error rates"></a><br><sub>Analytics (6/6): Detection funnel, Performance, Throughput, Check error rates</sub></td>
  </tr>
</table>

#### Machine learning

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/model-lab-2.png"><img src="docs/media/model-lab-2.png" alt="Model Lab: metric comparison and the realistic evaluation on unseen domains"></a><br><sub>Model Lab: metric comparison and the realistic evaluation on unseen domains</sub></td>
    <td width="50%" valign="top"><a href="docs/media/model-lab-3.png"><img src="docs/media/model-lab-3.png" alt="Model Lab: dataset composition, ROC and precision-recall curves"></a><br><sub>Model Lab: dataset composition, ROC and precision-recall curves</sub></td>
  </tr>
</table>

#### Threat intelligence

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/domain.png"><img src="docs/media/domain.png" alt="Domain intelligence: every scan of a domain, its risk trend and the latest result"></a><br><sub>Domain intelligence: every scan of a domain, its risk trend and the latest result</sub></td>
    <td width="50%" valign="top"><a href="docs/media/feeds.png"><img src="docs/media/feeds.png" alt="Threat feeds: OpenPhish, PhishTank, URLhaus, Phishing.Database and Phishing Army with search and statistics"></a><br><sub>Threat feeds: OpenPhish, PhishTank, URLhaus, Phishing.Database and Phishing Army with search and statistics</sub></td>
  </tr>
</table>

#### Monitoring

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/activity.png"><img src="docs/media/activity.png" alt="Activity log: audit trail of scans, reports, votes, bulk jobs and settings changes"></a><br><sub>Activity log: audit trail of scans, reports, votes, bulk jobs and settings changes</sub></td>
    <td width="50%" valign="top"><a href="docs/media/alerts.png"><img src="docs/media/alerts.png" alt="Alerts raised by high-risk scans, watchlist changes and community verification"></a><br><sub>Alerts raised by high-risk scans, watchlist changes and community verification</sub></td>
  </tr>
</table>

#### Community

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/community.png"><img src="docs/media/community.png" alt="Community: PhishTank-style reports with voting"></a><br><sub>Community: PhishTank-style reports with voting</sub></td>
  </tr>
</table>

#### Developer API

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/api-docs.png"><img src="docs/media/api-docs.png" alt="Interactive Swagger documentation served by FastAPI at /docs"></a><br><sub>Interactive Swagger documentation served by FastAPI at /docs</sub></td>
    <td width="50%" valign="top"><a href="docs/media/api-guide.png"><img src="docs/media/api-guide.png" alt="API Guide: copy-paste examples for the REST API"></a><br><sub>API Guide: copy-paste examples for the REST API</sub></td>
  </tr>
</table>

#### Administration

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/settings.png"><img src="docs/media/settings.png" alt="Settings: verdict thresholds, network checks, optional API keys and data retention"></a><br><sub>Settings: verdict thresholds, network checks, optional API keys and data retention</sub></td>
  </tr>
</table>

#### Dark mode

<table>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/dark-analytics.png"><img src="docs/media/dark-analytics.png" alt="Analytics in dark mode"></a><br><sub>Analytics in dark mode</sub></td>
    <td width="50%" valign="top"><a href="docs/media/dark-overview.png"><img src="docs/media/dark-overview.png" alt="Overview in dark mode"></a><br><sub>Overview in dark mode</sub></td>
  </tr>
  <tr>
    <td width="50%" valign="top"><a href="docs/media/dark-report.png"><img src="docs/media/dark-report.png" alt="Scan report in dark mode"></a><br><sub>Scan report in dark mode</sub></td>
  </tr>
</table>

#### Mobile

<table>
  <tr>
    <td width="33%" valign="top"><a href="docs/media/mobile-overview.png"><img src="docs/media/mobile-overview.png" alt="Overview on a phone (390x844)"></a><br><sub>Overview on a phone (390x844)</sub></td>
    <td width="33%" valign="top"><a href="docs/media/mobile-report.png"><img src="docs/media/mobile-report.png" alt="Scan report on a phone"></a><br><sub>Scan report on a phone</sub></td>
  </tr>
</table>

</details>

<!-- MEDIA-GALLERY:END -->

## Architecture

```mermaid
flowchart LR
    subgraph Clients
        UI["React dashboard<br/>Vite + TypeScript"]
        EXT["Chrome extension<br/>Manifest V3"]
        CLI["Scripts / curl<br/>REST API"]
    end
    UI --> API
    EXT --> API
    CLI --> API
    API["FastAPI app<br/>routers"] --> SCAN["Scan pipeline<br/>services/scanner.py"]
    SCAN --> ML["ML predictor<br/>4 scikit-learn models<br/>+ explanations"]
    SCAN --> ENG["Analysis engine<br/>analysis/engine.py"]
    SCAN --> FEEDS[("Threat feeds<br/>OpenPhish, PhishTank,<br/>URLhaus, ...")]
    ENG --> GUARD["SSRF guard<br/>net_safety.py"]
    GUARD --> SITE(("Scanned<br/>website"))
    ENG --> INTEL["DNS, WHOIS/RDAP, GeoIP,<br/>DNS blocklists, Tranco"]
    ENG --> BRAND["Brand + content<br/>analysis"]
    ML --> SCORE["Risk scoring<br/>scoring.py"]
    ENG --> SCORE
    FEEDS --> SCORE
    SCORE --> DB[("SQLite<br/>scans, reports, watchlist,<br/>alerts, events")]
    DB --> INSIGHT["Analytics, history,<br/>graph, timeline"]
    INSIGHT --> API
    JOBS["Background jobs<br/>watchlist scheduler,<br/>bulk workers"] --> SCAN
```

A scan, step by step:

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant FE as Dashboard
    participant API as FastAPI
    participant S as Scanner
    participant ML as ML predictor
    participant E as Analysis engine
    participant F as Threat feeds
    participant DB as SQLite
    U->>FE: Paste URL (Deep scan on)
    FE->>API: POST /api/scan {url, deep: true}
    API->>S: perform_scan()
    S->>S: Validate and normalise the URL
    par In parallel
        S->>ML: predict(url)
        ML-->>S: Probability, 4 model scores, top features
    and
        S->>E: run_checks(url, settings)
        E-->>S: 50+ checks, heuristic score, WHOIS/DNS/SSL/HTTP/brand/content
    and
        S->>F: lookup(url)
        F-->>S: Feed hits
    end
    S->>DB: Community status of the URL/domain
    S->>S: Combine scores, apply floors and caps, set tier, threat type and summary
    S->>DB: Save scan and HTML snapshot, log event, raise alert if high risk
    S-->>API: ScanResult
    API-->>FE: JSON
    FE-->>U: Report page /scans/{id}
```

Component-by-component details (pages, routers, services, engine modules, ML, database tables, background jobs, the Vercel wrapper and the safety measures) are in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Machine learning

### Datasets

All training data is read from local snapshots, so training is reproducible offline. The numbers come from [`backend/ml/artifacts/metrics.json`](backend/ml/artifacts/metrics.json) (model version `2026.10.24-1812`).

| Class | Source | URLs |
|---|---|---:|
| Phishing | [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI #967) | 45,000 |
| Phishing | [PhishTank](https://phishtank.org/) verified-online feed | 16,000 |
| Phishing | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) active hosts | 12,000 |
| Phishing | [OpenPhish](https://openphish.com/) community feed | 241 |
| Legitimate | PhiUSIIL legitimate URLs, augmented (see below) | 40,753 |
| Legitimate | [Tranco](https://tranco-list.eu/) top-30k domains, augmented | 21,825 |
| Legitimate | Real sub-domain hosts from the Tranco list | 6,448 |
| Legitimate | Real deep links from public sitemaps of Tranco domains | 4,097 |
| **Total** | **73,241 phishing + 73,123 legitimate** | **146,364** |

The split is **80/20 (117,092 train / 29,272 test)** with `StratifiedGroupKFold`, grouped by campaign key or domain, so no campaign appears in both train and test.

Bias handling in [`backend/ml/train.py`](backend/ml/train.py):

- **Bare homepages.** All PhiUSIIL legitimate URLs are bare `https://www.<domain>` homepages, so "has a path" would look like a phishing signal. Legitimate hosts are augmented (www toggled, about 40% get a realistic synthetic deep-link path, some get a query string) and mixed with real deep links and real sub-domain hosts.
- **Bare hosts.** Phishing.Database lists hosts only. Their scheme is filled in at PhishTank's HTTPS rate (0.93), and 41% of the training hosts borrow the path of a random training PhishTank URL, so "bare host" does not become a phishing signal.
- **Duplicate campaigns.** Phishing URLs are deduplicated across sources and capped at 3 per campaign key (the registered domain, or the tenant host on free-hosting platforms).
- **Identical normalisation.** Every URL is lower-cased and its trailing slash stripped, in training and at prediction time ([`backend/ml/features.py`](backend/ml/features.py)).

### Features

The extractor computes **44 lexical features** from the URL string alone, with no network access, so a prediction takes milliseconds.

| Group | Features |
|---|---|
| Length and counts | URL, hostname, path and query length; dots, hyphens, underscores, `@`, `?`, `=`, `&`, slashes, special characters, digits, digit ratio, digits and hyphens in the host |
| Host structure | Number of sub-domains, sub-domain length, registered-domain length, TLD length, raw IP host, explicit port, punycode |
| Randomness | Domain and URL entropy, vowel ratio of the domain, longest and average token length, long hex/random tokens, percent-encoding |
| Known-bad patterns | Suspicious keywords (login, verify, ...), abused TLDs, URL shorteners, free hosting / user-content platforms, suspicious file extensions, `//` redirect in the path, `http` token inside the host or path, path depth, number of query parameters |
| Brand abuse | Brand name outside its official domain, brand in a sub-domain, look-alike brand (for example `amaz0n`), embedded domain (for example `apple.com.evil.ru`) |

The most important features of the Random Forest are sub-domain length, free hosting, hostname length, suspicious TLD and URL entropy.

### Models and results

| Model | Configuration |
|---|---|
| Logistic Regression | StandardScaler + LogisticRegression (C = 1.0) |
| Decision Tree | max depth 20, min 5 samples per leaf |
| **Random Forest** | 150 trees, min 2 samples per leaf |
| Support Vector Machine | StandardScaler + Nyström RBF kernel approximation (500 components) + LinearSVC, probability-calibrated |

**Hold-out test split** (29,272 URLs from campaigns not seen in training):

<!-- ML-METRICS:START -->
<!-- generated from backend/ml/artifacts/metrics.json; scripts/capture_media.py --readme-metrics can regenerate this block -->

Model version `2026.10.24-1812` (trained 2026-10-24 18:12 UTC) on **146,364 URLs** (73,241 phishing / 73,123 legitimate; 117,092 train / 29,272 test) with **44 lexical features**. Best model: **Random Forest** (highest test F1).

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | 5-fold CV F1 | Train time |
|---|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 82.4% | 90.6% | 72.4% | 80.5% | 0.902 | 80.5% ± 0.1 | 0.364 s |
| Decision Tree | 84.9% | 91.2% | 77.4% | 83.7% | 0.921 | 83.7% ± 0.3 | 0.466 s |
| **Random Forest** | 86.4% | 90.8% | 81.0% | 85.6% | 0.945 | 85.5% ± 0.2 | 1.551 s |
| Support Vector Machine | 84.6% | 91.0% | 76.8% | 83.3% | 0.933 | 83.7% ± 0.2 | 8.817 s |

<!-- ML-METRICS:END -->

Random Forest confusion matrix on the test split: 13,422 true negatives, 1,202 false positives, 2,786 false negatives and 11,862 true positives.

**Realistic evaluation (`modern_eval`).** A separate set of **4,000 URLs** that was never used for training or model selection: 1,000 PhishTank and 1,000 Phishing.Database URLs whose campaign keys never appear in training, and 2,000 legitimate deep links from domains ranked 30,001-60,000 on Tranco (all excluded from the legitimate training data). This is closer to what the system meets in real use.

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | False-positive rate | HTTPS phishing recall | PhishTank recall | Phishing.Database recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 88.8% | 95.2% | 81.8% | 88.0% | 0.972 | 4.1% | 82.1% | 86.0% | 77.6% |
| Decision Tree | 84.0% | 84.6% | 83.2% | 83.9% | 0.899 | 15.2% | 83.4% | 91.3% | 75.1% |
| **Random Forest** | 86.4% | 87.7% | 84.7% | 86.2% | 0.942 | 11.9% | 84.8% | 93.3% | 76.1% |
| Support Vector Machine | 86.9% | 89.8% | 83.2% | 86.4% | 0.945 | 9.4% | 83.4% | 88.1% | 78.3% |

All numbers are regenerated by `python -m ml.train` and shown live on the Model Lab page.

### Why Random Forest

- It has the **highest F1 (85.6%) and ROC-AUC (0.945) on the hold-out test split**, which is the selection rule in `train.py`, and its 5-fold cross-validated F1 (85.5% ± 0.2) shows the result is stable.
- On the realistic set it **catches the most phishing**: the highest recall (84.7%), the highest recall on HTTPS phishing (84.8%) and 93.3% of the unseen PhishTank URLs.
- It handles mixed count, ratio and binary features without scaling, captures interactions (for example "brand word + free hosting"), and gives feature importances for the Model Lab.
- The trade-off is honest: Logistic Regression has fewer false positives on the realistic set (4.1% against 11.9%). PhishGuard compensates on the scoring side. The ML probability is only 60% of the final score, and popular or official domains with no blocklist hit are capped (see [Risk scoring](#risk-scoring)).

### The HTTPS-bias fix

In the training data, only 62.7% of phishing URLs use HTTPS against 92.5% of legitimate ones. In the realistic set, 90.3% of phishing URLs use HTTPS. A model that sees the scheme learns the shortcut "http means phishing", which no longer holds. So `train.py` trains **two feature variants**:

| Variant | Features | Random Forest test F1 | Random Forest realistic F1 | HTTPS phishing recall |
|---|---:|---:|---:|---:|
| With the scheme (`uses_https`) | 45 | 93.4% | 86.5% | 83.7% |
| **Without any scheme feature (kept)** | **44** | **85.6%** | **86.2%** | **84.8%** |

The with-scheme variant looks much better on the test split, but most of that gain is the shortcut and disappears on the realistic set. The rule keeps the scheme-free variant unless its realistic F1 is more than 0.5 points lower, so the deployed model is the 44-feature one. The Phishing.Database scheme imputation and identical URL normalisation (above) remove the same shortcut from the data side.

### Explanation method

The report's **ML Explanation** tab shows how each feature moved this prediction. It uses a perturbation method on the best model:

1. Take the URL's feature vector.
2. For every feature whose value differs from a typical legitimate URL (the median of the legitimate training URLs, stored in `metrics.json` as `legit_median`), set that one feature to the median and predict again.
3. The change in phishing probability is the feature's signed impact: **risk** if the real value raises the probability, **safe** if it lowers it.

The 10 largest impacts are shown. The Model Lab page also shows the global Random Forest feature importance and the per-class feature averages.

## Risk scoring

The final score combines the ML model with the live checks and then applies a few hard rules. The code is in [`backend/app/scoring.py`](backend/app/scoring.py) and in `score_checks()` in [`backend/app/analysis/engine.py`](backend/app/analysis/engine.py).

```text
heuristic = 100 x (1 - e^(-raw / 18)),   raw = sum(weights of failed checks) + 0.4 x sum(weights of warnings)
risk      = round(0.6 x ML phishing probability x 100  +  0.4 x heuristic)
```

**Heuristic floors.** Strong single signals set a minimum heuristic score:

| Signal | Minimum heuristic score |
|---|---:|
| Listed on a threat-intelligence blocklist | 92 |
| Brand impersonation together with a login form | 85 |
| Password form posting to another domain | 80 |
| Brand impersonation | 75 |
| Suspicious JavaScript | 60 |
| Raw IP host, or a domain younger than 30 days | 55 |
| Excessive or cross-domain redirects, or a punycode homograph | 50 |
| Invalid SSL certificate | 45 |
| High-risk TLD | 35 |

**Heuristic caps.** The heuristic is capped at 15 for an official brand domain, and at 20 for a Tranco top-10k site with no hard signal (brand impersonation, off-site password form, suspicious JavaScript, DNS blocklist hit or private network host).

**Final score rules.**

- A blocklist or feed hit raises the risk to **at least 90**. A verified community report raises it to **at least 85**.
- A popular site (Tranco top 10k) or an official brand domain with no blocklist, feed or community hit is **capped at 30**. This is never applied to hosting, user-content or shortener platforms, where the domain's popularity says nothing about the page.

**Verdict and tier.** The thresholds are **35** (suspicious) and **65** (phishing) and can be changed in Settings.

| Risk score | Verdict | Trust tier |
|---|---|---|
| 0-14 | Legitimate | Trusted |
| 15-34 | Legitimate | Favorable |
| 35-49 | Suspicious | Neutral |
| 50-64 | Suspicious | Questionable |
| 65-100 | Phishing | Untrusted |

- **Trust score** = 100 - risk.
- **Confidence** is the distance from the nearest threshold, divided by the width of that verdict band (0-1). It is at least 0.9 when a blocklist or a community verdict decided the result.
- **Threat type** is the first that applies:
  - `malware`: listed by a malware engine (URLhaus), or the URL points to an executable or archive file and the verdict is not legitimate.
  - `social_engineering`: listed by a phishing feed or engine, brand impersonation, a login or password form on a suspicious site, or a phishing verdict.
  - `unwanted_software`: a parked domain, or a spam-blocklist listing while the verdict is not legitimate.
  - `none`: no evidence (always for a capped popular or official domain).
- **Tested depth** is `lexical` when only the URL and the ML model were used (quick scan, or network checks turned off). The UI then shows "Untested (lexical only)".
- Each report also has a **score breakdown**, lists of **positive and negative factors**, and a plain-English **summary** of two to four sentences.

## Tech stack

| Layer | Technology |
|---|---|
| Machine learning | Python 3.12, scikit-learn 1.9, pandas, NumPy, joblib, tldextract |
| Backend API | FastAPI, Uvicorn, Pydantic 2, httpx (async), SQLite (WAL mode) |
| Network intelligence | dnspython, python-whois with RDAP fallback, Beautiful Soup 4, ip-api.com / ipwho.is (GeoIP), Tranco list (mmh3-hashed index), langdetect |
| Frontend | React 19, TypeScript 6, Vite 8, Tailwind CSS 4, Recharts 3, TanStack Query 5, React Router 7, d3-force, lucide-react, jsQR |
| Browser extension | Chrome Manifest V3, plain JavaScript (no build step) |
| Hosting | Vercel: static frontend plus one Python function (`api/index.py`) in demo mode |
| Tooling | oxlint; Playwright, Pillow and FFmpeg for the README media |

## Project structure

```text
phishguard/
├── api/
│   └── index.py                  # Vercel Python function entry point (imports deploy/cloud_app.py)
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, startup tasks, router registration
│   │   ├── db.py                 # SQLite schema + idempotent migration
│   │   ├── scoring.py            # risk score, verdict, tier, trust score, threat type, factors, summary
│   │   ├── routers/              # scans, bulk, tools, community, watchlist, insights, misc (alerts, feeds, analytics, ...)
│   │   ├── services/             # scanner pipeline, bulk workers, watcher, analytics, graph, similar, events, seed, ...
│   │   └── analysis/             # engine.py + net_safety, dnsbl, feeds, brands, typosquat, content, popularity, rdap, text_extract
│   ├── ml/
│   │   ├── features.py           # lexical feature extractor (shared by training and prediction)
│   │   ├── train.py              # dataset build, bias handling, training, evaluation, artifacts
│   │   ├── predictor.py          # loads the models, predicts, explains
│   │   ├── collect_legit.py      # optional: collects real legitimate deep links from sitemaps
│   │   ├── data/                 # built datasets; raw/ holds the downloaded sources (git-ignored)
│   │   └── artifacts/            # trained models (*.joblib) + metrics.json
│   ├── data/                     # runtime data: SQLite DB, threat feeds, Tranco index
│   ├── README.md
│   └── requirements.txt
├── deploy/                       # Vercel demo mode: cloud_app.py, seed.db snapshot, packed feeds, build + preflight scripts
├── docs/
│   ├── ARCHITECTURE.md           # detailed architecture
│   ├── DEMO_GUIDE.md             # 5-minute viva demo script
│   ├── DEPLOY_NOTES.md           # Vercel deployment rehearsal notes
│   ├── FEATURES.md               # research of the 12 URL-safety tools
│   ├── SPEC.md, SPEC_V2.md       # build specifications (SPEC_V2 starts with the mini-project scope)
│   ├── FE_V2_CONTRACT.md         # frontend data contract
│   └── media/                    # screenshots, demo video, manifest.json
├── extension/                    # Chrome extension: background.js, popup/, options/, content/banner.js, icons/
├── frontend/                     # React + Vite dashboard: src/pages, src/pages/report, src/components, src/api, ...
├── scripts/
│   └── capture_media.py          # screenshot / video / README gallery generator
├── requirements.txt              # pinned runtime packages of the Vercel function
├── start.sh                      # one-command local start (API :8000 + dashboard :5173)
├── vercel.json
└── .vercelignore
```

## Getting started

### Prerequisites

- **Python 3.12**, with `venv` + `pip` (or [uv](https://docs.astral.sh/uv/))
- **Node.js 20+** and npm (Vite 8 needs Node 20.19+ or 22.12+)
- Git, and internet access for the live checks (DNS, WHOIS, HTTP) and the first threat-feed download
- Optional: the `whois` command-line tool. Without it, WHOIS falls back to RDAP.

### Quick start (macOS / Linux)

```bash
git clone https://github.com/at9501264-stack/mini-project.git phishguard
cd phishguard
./start.sh
```

`start.sh` does everything in one command:

1. Creates `backend/.venv` (with uv if installed, otherwise `python3 -m venv`) and installs `backend/requirements.txt` on the first run.
2. Trains the model only if `backend/ml/artifacts/metrics.json` is missing (the trained models are included).
3. Runs `npm install` in `frontend/` on the first run.
4. Starts the API on port 8000 and the dashboard on port 5173. Ctrl+C stops both.

Then open:

- Dashboard: <http://localhost:5173>
- API docs: <http://localhost:8000/docs>

Two optional packages add the Tranco popularity rank (`mmh3`) and page-language detection (`langdetect`). If they are missing, those two signals are reported as unavailable and everything else works. Install them once with:

```bash
backend/.venv/bin/pip install mmh3 langdetect
```

On first start, an empty database is filled with demo scans spread over the last 30 days, and the threat feeds are downloaded in the background. Set `PHISHGUARD_NO_SEED=1` to start with an empty database.

### Windows

`start.sh` is a bash script that expects the macOS/Linux virtual-environment layout. On Windows, run the two parts in two terminals (PowerShell), or use WSL and `./start.sh`.

Terminal 1, the API:

```powershell
git clone https://github.com/at9501264-stack/mini-project.git phishguard
cd phishguard\backend
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt mmh3 langdetect
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

Terminal 2, the dashboard:

```powershell
cd phishguard\frontend
npm install
npm run dev
```

Open <http://localhost:5173>. If PowerShell blocks `npm` scripts, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

### Backend (manual setup, macOS / Linux)

```bash
cd backend
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt mmh3 langdetect
.venv/bin/uvicorn app.main:app --port 8000      # http://localhost:8000/docs
```

With uv: `uv venv .venv --python 3.12` and `uv pip install --python .venv/bin/python -r requirements.txt mmh3 langdetect`.

### Training the model (optional)

The trained models are already in `backend/ml/artifacts/`. To retrain, put the raw data in `backend/ml/data/raw/` (this folder is git-ignored):

| File in `backend/ml/data/raw/` | Where to get it | Needed |
|---|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | [UCI dataset #967](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (download and unzip) | Yes |
| `top-1m.csv` | [Tranco list](https://tranco-list.eu/) (registered domains) | Yes |
| `feeds_snapshot_20261024/` with `phishtank.csv`, `phishing_database.txt`, `openphish.txt` | A copy of `backend/data/feeds/` after the API has downloaded the feeds (the folder name is set as `SNAP` in `train.py`) | Yes |
| `tranco_sub/top-1m.csv` | Tranco list that includes sub-domains | Optional |
| `sitemaps/legit_deeplinks.csv` | `python -m ml.collect_legit` (needs internet, reads public sitemaps politely) | Optional |

```bash
cd backend
.venv/bin/python -m ml.collect_legit   # optional: real legitimate deep links from public sitemaps
.venv/bin/python -m ml.train           # about 2 minutes; writes ml/artifacts/*.joblib + metrics.json
```

On Windows use `.venv\Scripts\python -m ml.train`. Restart the API afterwards so it loads the new models.

### Frontend

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api, /docs, /redoc and /openapi.json to :8000
npm run build        # type-check + production build into frontend/dist
npm run lint         # oxlint
```

To point the dev server at another backend: `PHISHGUARD_API=http://127.0.0.1:8001 npm run dev`.

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PHISHGUARD_DB_PATH` | `backend/data/phishguard.db` | SQLite database file (created and migrated on startup) |
| `PHISHGUARD_NO_SEED` | unset | `1` = do not load demo data into an empty database |
| `PHISHGUARD_NO_SCHEDULER` | unset | `1` = do not start the background watchlist / retention scheduler |
| `PHISHGUARD_CLOUD` | unset | `1` = hosted demo mode: `GET /api/health` returns `cloud: true` and the dashboard shows the demo banner |
| `PHISHGUARD_API` (frontend dev server) | `http://localhost:8000` | Backend that Vite proxies `/api` to |
| `CRON_SECRET` (Vercel only, optional) | unset | If set, `/api/_cron` requires `Authorization: Bearer <CRON_SECRET>`; if unset, only Vercel's own cron requests are accepted |

Verdict thresholds, network checks, DNS blocklists, RDAP, screenshots, the request timeout, data retention and the optional Google Safe Browsing / VirusTotal API keys are set on the **Settings** page and stored in the database. Keys are masked in API responses.

## Load the Chrome extension

1. Start the backend on `http://localhost:8000` (and, optionally, the dashboard on `http://localhost:5173`).
2. Open `chrome://extensions` in Chrome (or another Chromium browser) and turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension/` folder.
4. Pin PhishGuard from the puzzle-piece menu so the badge is visible.
5. Optional: open the extension's **Options** to change the backend or dashboard URL, or turn auto-scan and the warning banner on or off.

Auto-scan runs a quick (URL-only) scan on each page you open and caches the result for 30 minutes. "Scan this page" in the popup runs a deep scan. The extension only has access to `localhost:8000` by default; other origins and the in-page banner ask for permission when you turn them on.

## Deploying to Vercel

The repository deploys as one Vercel project, configured in [`vercel.json`](vercel.json):

- The **frontend** is built with Vite and served as static files from `frontend/dist`. Every other path falls back to `index.html`.
- **`/api/*`, `/docs`, `/redoc` and `/openapi.json`** are rewritten to one Python function, [`api/index.py`](api/index.py) (region `bom1`, Mumbai; up to 300 s per request). It loads [`deploy/cloud_app.py`](deploy/cloud_app.py), which prepares the read-only serverless environment and then imports the unchanged FastAPI app.
- [`requirements.txt`](requirements.txt) at the repository root pins the function's packages to the versions that trained the models, because scikit-learn model files must be loaded by the same scikit-learn version.
- [`.vercelignore`](.vercelignore) keeps the upload under the 100 MB CLI limit (no raw datasets, local database, extension, scripts or media).

Step by step:

1. **Install the Vercel CLI and log in.**

   ```bash
   npm install -g vercel
   vercel login
   ```

2. **Link the folder to the Vercel project** (run in the repository root):

   ```bash
   vercel link --yes --project phishguard-mini-project
   ```

3. **Build the cloud snapshot** from your local data. This copies `backend/data/phishguard.db` to `deploy/seed.db` (removing API keys and other secrets, closing unfinished bulk jobs, shrinking stored HTML) and packs the threat feeds into `deploy/feeds/*.gz` (31 MB to about 8 MB) plus a prebuilt feed index:

   ```bash
   backend/.venv/bin/python deploy/build_cloud_seed.py
   ```

4. **Run the pre-flight checks**: upload and bundle size, Python requirements against the actual imports, and snapshot freshness. The output must end with `PREFLIGHT OK`. Add `--smoke` to also start the cloud app locally on a free port and call `/api/health`, `/api/_diag`, `/api/scans` and a deep `POST /api/scan`:

   ```bash
   backend/.venv/bin/python deploy/preflight.py
   ```

5. **Deploy to production** (optionally build the frontend first with `cd frontend && npm run build`, the same build Vercel runs):

   ```bash
   vercel deploy --prod --yes
   ```

   To try a build first, `vercel deploy --yes` makes a protected preview deployment.

6. **Verify** with `curl -s https://phishguard-mini-project.vercel.app/api/health`, which should report `"status":"ok"` and `"cloud":true`, and open `/docs`.
7. Optional: add a `CRON_SECRET` environment variable in the Vercel project settings. Without it, `/api/_cron` accepts only Vercel's own cron requests.

The full notes from the deployment rehearsal, with verification commands and troubleshooting, are in [docs/DEPLOY_NOTES.md](docs/DEPLOY_NOTES.md).

**What demo mode changes** (`deploy/cloud_app.py` sets these defaults; Vercel project variables win):

- `PHISHGUARD_CLOUD=1`: `/api/health` reports `cloud: true`, and the dashboard shows "Demo mode - data resets periodically."
- `PHISHGUARD_DB_PATH=/tmp/phishguard.db`: on every cold start, the bundled `deploy/seed.db` is copied to `/tmp`, so new scans, reports and watchlist items **disappear when the function restarts**. The demo timestamps are shifted forward so the "last 24h / 7d / 30d" charts are never empty.
- `PHISHGUARD_NO_SEED=1` and `PHISHGUARD_NO_SCHEDULER=1`: no demo seeding and no background loop. Instead, a **Vercel Cron job runs daily at 02:30 UTC** (`/api/_cron`): it checks up to 5 due watchlist items and applies data retention.
- Threat feeds are unpacked from `deploy/feeds/*.gz` into `/tmp` instead of being downloaded at startup, and the Tranco rank comes from the bundled `.npz` index.
- Data lives in each function instance's `/tmp`, so two visitors can briefly see different data, and a manual feed refresh lasts only for that instance.
- The optional API keys are removed from the snapshot, so the Google Safe Browsing and VirusTotal integrations are off in the demo.
- WHOIS uses RDAP, because the Vercel runtime has no `whois` binary. Live checks run from Vercel's servers, so results can differ from a local run.
- An extra diagnostics route, `GET /api/_diag`, reports the runtime state (Python, `/tmp`, DNS, cold-start timings).
- There is no login or rate limiting. Do not put private data or real API keys into the public demo.

## API reference

Interactive documentation is served at **`/docs`** (Swagger UI) and **`/redoc`**. On the live demo: <https://phishguard-mini-project.vercel.app/docs>. All endpoints are under `/api`, use JSON and return ISO-8601 UTC timestamps.

| Area | Endpoints | Purpose |
|---|---|---|
| Scans | `POST /api/scan` | Scan a URL: `{"url": "...", "deep": true}` returns the full ScanResult (`deep: false` = URL + ML only) |
| | `GET /api/scans` | History with filters `q, verdict, source, tld, brand, min_risk, max_risk, date_from, date_to`, pivots `ip, asn, registrar, category, threat_type, tier`, plus `sort, order, page, page_size` |
| | `GET`, `PATCH`, `DELETE /api/scans/{id}` · `POST /api/scans/{id}/rescan` | Read, tag/annotate, delete or re-run a scan |
| | `GET /api/scans/{id}/compare/{other_id}` | Field-by-field difference of two scans |
| | `GET /api/scans/export?format=csv\|json` | Export with the same filters |
| | `GET /api/scans/{id}/dom` · `/timeline` · `/similar` | Stored HTML, event timeline, scans on the same IP/ASN/registrar |
| Domains and graph | `GET /api/domains/{domain}` · `GET /api/graph?domain=&scan_id=&depth=&limit=` | Per-domain intelligence and risk trend; relationship graph |
| Bulk | `POST /api/bulk` · `POST /api/bulk/upload` · `GET /api/bulk` · `GET /api/bulk/{id}` | Batch jobs of up to 500 URLs |
| Tools | `POST /api/extract` · `GET /api/typosquat?domain=` | URLs from email/SMS text; look-alike domains |
| Community | `POST /api/reports` · `GET /api/reports` · `GET /api/reports/{id}` · `POST /api/reports/{id}/vote` | Reports and votes |
| Watchlist | `POST`, `GET /api/watchlist` · `DELETE /api/watchlist/{id}` · `POST /api/watchlist/{id}/run` · `GET /api/watchlist/{id}/history` | Monitoring |
| Alerts | `GET /api/alerts` · `POST /api/alerts/{id}/read` · `POST /api/alerts/read-all` | Alerts |
| Threat feeds | `GET /api/feeds` · `POST /api/feeds/refresh` · `GET /api/feeds/search?q=` | Feed status, refresh, search |
| Analytics | `GET /api/analytics/overview` · `timeseries` · `distribution` · `model` · `performance` · `funnel` | Dashboard data (`range=24h\|7d\|30d\|90d\|all`) |
| Activity, settings, system | `GET /api/events` · `GET`, `PUT /api/settings` · `GET /api/health` · `GET /api/stats/live` | Audit log, configuration, health, live feed |
| Admin | `POST /api/admin/seed` · `GET /api/admin/seed` · `POST /api/admin/reset` | Demo data |

Example:

```bash
curl -s -X POST http://localhost:8000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url": "http://paypal-login-verify.secure-account.xyz/update", "deep": true}' \
  | jq '{verdict, risk_score, trust_score, tier, threat_type, summary}'
```

## Usage guide

1. **Scan a URL.** On the **Scan** page, paste a URL and keep **Deep scan** on to run the DNS, WHOIS, SSL, HTTP and content checks. Turn it off for an instant URL-only check. The search box in the header always runs a quick, URL-only scan. The **Email / SMS text** tab pulls every link out of a pasted message, including defanged ones. The **QR code** tab decodes an image in your browser.
2. **Read the report.** The header shows the risk gauge, the verdict, the trust score and tier, the threat type and how many engines flagged the URL. The tabs:
   - **Summary**: plain-English summary, score breakdown, positive and negative factors, and every check grouped by category.
   - **ML Explanation**: the four model probabilities and the features behind them.
   - **Domain, Geo & Hosting, SSL, HTTP**: the raw evidence.
   - **Content, Resources, Source**: what the page is about, what it loads, and its HTML.
   - **Brand** and **Reputation**: look-alike detection, detection engines, feed hits and community votes.
   - **Screenshot** (when enabled), **Graph**, **Timeline** and **Raw JSON**.

   The header buttons let you rescan, add tags and notes, compare with another scan of the domain, export JSON, print or copy a link to the report. The Reputation tab has "phishing" and "legitimate" vote buttons that create or join a community report.
3. **Scan in bulk.** On **Bulk Scan**, paste up to 500 URLs or upload a CSV/TXT file. The job runs in the background, and its results can be filtered and exported.
4. **Monitor.** On **Watchlist**, add a URL or domain with a check interval and, optionally, typosquat monitoring. Alerts appear in the bell menu and on the **Alerts** page when the verdict changes or a new look-alike domain starts resolving.
5. **Investigate.** **History** filters and exports every scan; click an IP, ASN, registrar, category or tier to pivot. **Graph** shows how domains share infrastructure. **Typosquat** lists look-alikes of a domain. **Threat Feeds** searches the local blocklists.
6. **Contribute.** On **Community**, report a phishing (or wrongly flagged) URL and vote on other reports.
7. **Tune.** On **Settings**, change the suspicious and phishing thresholds, turn network checks, DNS blocklists, RDAP or screenshots on or off, set data retention and add optional Google Safe Browsing / VirusTotal keys.

A 5-minute walkthrough for presentations is in [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

## Testing and verification

- **Model evaluation** ([`backend/ml/train.py`](backend/ml/train.py)): a group-aware 80/20 hold-out split, 5-fold cross-validated F1, and the separate realistic set from unseen campaigns and less-popular legitimate sites. Every number on the Model Lab page comes from `metrics.json`.
- **Deployment checks** ([`deploy/preflight.py`](deploy/preflight.py)): bundle size limits, a dependency audit and snapshot freshness; `--smoke` rehearses the cloud function locally.
- **Frontend**: `npm run build` (TypeScript type-check and production build) and `npm run lint` (oxlint).
- **End-to-end UI check**: [`scripts/capture_media.py`](scripts/capture_media.py) opens every page, report tab, dark mode and the mobile layout in a headless browser, and records error boxes, failed API calls and blank pages in `docs/media/manifest.json`.
- **Manual test set**: known phishing URLs from the feeds, look-alike URLs such as `paypa1-secure-login.com/verify`, and popular sites such as `google.com` and `wikipedia.org` to check for false positives.

There is no automated unit-test suite (pytest/vitest) yet.

## Limitations and ethical use

- PhishGuard is an **educational prototype** built for a B.Tech mini project and runs on demo data. It gives a preliminary assessment, it is **not a replacement for professional security products**, and its verdicts can be wrong in both directions.
- The ML model sees **only the URL string** (lexical features). Phishing pages on clean-looking URLs, especially on large trusted platforms, can slip through, and unusual legitimate URLs can be flagged. On the realistic set, the Random Forest still misses about 15% of phishing URLs and flags about 12% of legitimate deep links before the live checks and caps are applied.
- Live checks depend on third-party services (WHOIS/RDAP, GeoIP, DNS blocklists, feeds) that may rate-limit, time out or be unreachable. Failed checks are marked as errors and do not crash the scan.
- **PhishGuard scans only public addresses.** The scanner refuses private, loopback, link-local and other non-public addresses (SSRF guard) and only connects on ports 80, 443, 8080 and 8443. Only scan sites you are allowed to check. PhishGuard fetches live phishing links from the server, so you never need to open them in your own browser, and you should not.
- Threat feeds are used under their own terms (several are free for non-commercial use only).
- The demo has no user accounts, login or rate limiting.

## Future scope

From the synopsis, with the current status:

| Synopsis item | Status |
|---|---|
| Browser extension for real-time URL checking | Done: Chrome Manifest V3 extension |
| Web-page content and HTML analysis | Done: HTTP and content checks, page category, resources, stored HTML |
| Integrate threat-intelligence sources | Done: 5 feeds, DNS blocklists, optional Safe Browsing / VirusTotal |
| Larger, continuously updated datasets | Partly done: about 146k labelled URLs from 5 sources, and the feeds can be refreshed from the Threat Feeds page. Scheduled retraining on fresh data is future work |
| Advanced ML and deep-learning models | Future: character-level CNN/LSTM or transformer URL models, gradient boosting, visual (screenshot) similarity |
| Mobile application | Future: the dashboard is responsive and works on phones, but there is no native app |

Other ideas: user accounts with API keys and rate limits, a headless-browser sandbox for JavaScript-heavy phishing kits, certificate-transparency monitoring for brand look-alikes, and automated takedown reports.

## Credits

- **Student:** Ayushi Tiwari, B.Tech Computer Science & Engineering
- **Project guide:** Mr. Vishal Gupta, Department of Computer Science & Engineering
- **Institute:** Lloyd Institute of Engineering & Technology, Greater Noida, Uttar Pradesh
- **University:** Dr. A.P.J. Abdul Kalam Technical University (AKTU), Lucknow

**Datasets and threat intelligence:** [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (UCI Machine Learning Repository), [Tranco](https://tranco-list.eu/) top-sites ranking, [PhishTank](https://phishtank.org/), [OpenPhish](https://openphish.com/), [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch), [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database), [Phishing Army](https://phishing.army/), DNS blocklists from Spamhaus, SURBL, URIBL and SpamCop, and GeoIP from ip-api.com and ipwho.is.

**Key libraries:** FastAPI, Uvicorn, Pydantic, scikit-learn, pandas, NumPy, joblib, httpx, dnspython, python-whois, tldextract, Beautiful Soup, langdetect, mmh3, React, Vite, TypeScript, Tailwind CSS, Recharts, TanStack Query, React Router, d3-force, lucide-react and jsQR, plus Playwright, Pillow and FFmpeg for the documentation media.

**Feature research:** VirusTotal, urlscan.io, Google Safe Browsing, PhishTank, OpenPhish, URLVoid, CheckPhish (Bolster), Sucuri SiteCheck, ScamAdviser, IPQualityScore, Norton Safe Web and Cisco Talos. PhishGuard is not affiliated with any of them.

**References from the synopsis:** Ma et al., "Beyond Blacklists: Learning to Detect Malicious Web Sites from Suspicious URLs" (KDD 2009); Le et al., "URLNet" (2018); Sahingoz et al., "Machine Learning Based Phishing Detection from URLs" (Expert Systems with Applications, 2019); Géron, *Hands-On Machine Learning*; Bishop, *Pattern Recognition and Machine Learning*; Han, Kamber and Pei, *Data Mining: Concepts and Techniques*.

No open-source license has been chosen yet, so all rights are reserved by the author. The third-party datasets and feeds keep their own licences and terms of use.
