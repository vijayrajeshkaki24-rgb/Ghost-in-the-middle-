# 👻 Ghost in the Middle: ACASE

**An Intelligent Framework for Detection and Mitigation of Adversary-in-the-Middle (AiTM) Attacks Through Automated Authentication Security Assessment**

> IEEE Conference on Network and Information Security (ICNIS-2025)
> Dept. of CSE (Cybersecurity), Chalapathi Institute of Engineering & Technology (Autonomous), Lam, Guntur, AP – 522034, India
> Academic Year 2025–2026

---

## 📌 Overview

Adversary-in-the-Middle (AiTM) attacks use reverse-proxy toolkits (Evilginx2, Modlishka, Muraena) to relay a live login session and steal the post-authentication session cookie. This bypasses MFA, because the attacker never needs the password or the second factor.

Traditional defences (WAF, IDS, Snort/Suricata, SIEM, header scanners) lack session-layer context. **ACASE (Automated Cookie and Session Evaluation)** proactively scans a target and finds the weaknesses that make AiTM attacks possible, *before* exploitation.

## ✨ Key Features

- **Three-module automated assessment**: authentication posture, session-token integrity, proxy-layer anomalies
- **Composite weighted risk-scoring model** (12+ indicators)
- **AI recommendation engine**: local LLM via Ollama generates remediation advice
- **Real-time React dashboard** with Chart.js visualisations
- **Automated PDF reports** (ReportLab)
- **Ownership verification**: email OTP before any scan is allowed
- **Dockerised** lab environment (Kali Linux, DVWA, Evilginx 2.4)

## 🏗️ Architecture

| Module | Weight | What it checks |
|---|---|---|
| **1. Authentication Security Analyzer** | 0.35 | HTTPS enforcement, HSTS (max-age ≥ 31,536,000 s), Content-Security-Policy, cookie flags: `Secure` (w=4), `HttpOnly` (w=2), `SameSite` (w=2) |
| **2. Session Token Validator** | 0.40 | Token length (w=3, min 32 chars), Shannon entropy (w=5, threshold ≥ 3.5 bits/char), expiration policy (w=3), session reuse (w=4), secure transmission (w=3) |
| **3. Proxy Detection Engine** | 0.25 | `X-Forwarded-For`, `Via`/`Forwarded` headers, abnormal redirect-chain depth, token reflection, TLS certificate anomalies (e.g. Let's Encrypt on enterprise domains), timing deviation > 100 ms over baseline |

**Risk score** = Σ (Vulnerability_Weight × Detection_Result)

| Band | Score | Action |
|---|---|---|
| 🟢 LOW | 0–4 | Monitor; apply best-practice hardening |
| 🟡 MEDIUM | 5–8 | Immediate header/cookie remediation |
| 🟠 HIGH | 9–14 | Urgent: multiple critical gaps present |
| 🔴 CRITICAL | 15+ | Halt deployment; severe risk |

### Shannon entropy check

```python
from math import log2

def token_entropy(token: str) -> float:
    freq = {c: token.count(c) / len(token) for c in set(token)}
    return -sum(p * log2(p) for p in freq.values())

if token_entropy(session_token) < 3.5:
    flag_vulnerability("LOW_ENTROPY", weight=5)
```

## 🔄 Workflow

1. User registers a target URL; an email OTP verifies ownership
2. API health check at `/api/health`; session token issued
3. Automated 14-module scan runs (30–90 s)
4. Risk score computed; Ollama LLM generates remediation recommendations
5. Dashboard renders results; PDF report is generated

## 🧰 Tech Stack

| Component | Technology |
|---|---|
| Core language | Python 3.11 |
| API | Flask 3.0 + Flask-CORS |
| Frontend | React 18 + Vite |
| Visualisation | Chart.js |
| HTTP analysis | Requests + BeautifulSoup4 |
| Data layer | Pandas + NumPy |
| AI engine | Ollama (local LLM) |
| Reporting | ReportLab |
| Test environment | Kali Linux, DVWA, Evilginx 2.4 |
| Containerisation | Docker |

## 🚀 Getting Started

> Adjust paths and names to match your repository.

### Prerequisites
- Python 3.11+, Node.js, Docker
- [Ollama](https://ollama.com) with a model pulled
- Kali Linux (recommended for the lab setup)

### Installation

```bash
# 1. Clone
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# 2. Configure
cp .env.example .env        # edit SMTP / Ollama settings (optional)

# 3. Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Frontend
cd acase-dashboard && npm install && cd ..
```

### Run

```bash
# One command (API + dashboard). Add --lab to also start DVWA + Ollama via Docker
./start_acase.sh
./start_acase.sh --lab

# Or manually:
python -m backend.app            # API on http://localhost:5000
cd acase-dashboard && npm run dev   # Dashboard on http://localhost:5173
```

Verify the API: `http://localhost:5000/api/health`


## 🗂️ Repository Structure

```
ghost-in-the-middle/
├── backend/
│   ├── app.py               # Flask API (register, verify, scan, results, PDF)
│   ├── config.py            # env-based settings
│   ├── otp.py               # email OTP gate (prints OTP to console if SMTP unset)
│   ├── ai_engine.py         # Ollama recommendations + rule-based fallback
│   ├── report.py            # ReportLab PDF generation
│   ├── storage.py           # JSON-file store
│   └── scanner/
│       ├── auth_analyzer.py     # Module 1
│       ├── session_validator.py # Module 2
│       ├── proxy_detector.py    # Module 3
│       ├── risk.py              # scoring + bands
│       ├── engine.py            # orchestrates a scan
│       └── http_probe.py, tls_info.py, utils.py
├── acase-dashboard/         # React 18 + Vite + Chart.js
├── tests/                   # pytest suite (entropy, scanner, API)
├── docs/                    # paper, figures, sample report
├── docker-compose.yml, start_acase.sh, .env.example, requirements.txt
└── LICENSE, SECURITY.md, CONTRIBUTING.md
```

## 🔌 API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/register` | `{email, url}`: sends OTP |
| POST | `/api/verify` | `{email, otp}`: returns `api_key` bound to the target host |
| POST | `/api/scan` | `{url}` + `X-API-Key`: runs the scan |
| GET | `/api/scans`, `/api/scans/<id>` | History / one result |
| GET | `/api/scans/<id>/report` | Download PDF report |

## ⚙️ Implementation Notes

This code implements the framework described in the paper. Where the paper does not specify a value, these choices were made (all tunable in `backend/scanner/`):

- Weights not given in the paper: HTTPS=3, HSTS=2, CSP=1, X-Forwarded-For=2, Via=1, Forwarded=1, redirect depth=2, TLS anomaly=2, timing=2, token reflection=3.
- Bands follow Table II: 0–4 LOW, 5–8 MEDIUM, 9–14 HIGH, 15+ CRITICAL. A module-weighted index (0.35 / 0.40 / 0.25) is also reported.
- "Session reuse" = the same token value is issued to two independent clients.
- "Expiration" fails when a cookie lifetime exceeds 7 days.
- "Timing deviation" = median response time minus fastest response over several requests, compared with 100 ms.
- The API key is bound to the registered host, so a key can only scan the host that was verified.

## 🧪 Tests

```bash
pip install -r requirements.txt
pytest -q
```

## 📊 Experimental Results

Six controlled scenarios on a Kali Linux lab (DVWA + Evilginx 2.4):

| TC | Scenario | Risk Score | Scan Time | Detected |
|---|---|---|---|---|
| TC-01 | Insecure cookie (Secure + HttpOnly absent) | 4 | 1.2 s | ✅ |
| TC-02 | Missing HSTS header | 3 | 0.8 s | ✅ |
| TC-03 | Weak session token entropy | 5 | 1.5 s | ✅ |
| TC-04 | Proxy headers (X-Forwarded-For) | 4 | 2.1 s | ✅ |
| TC-05 | Missing SameSite attribute | 2 | 0.9 s | ✅ |
| TC-06 | Live Evilginx 2.4 reverse-proxy simulation | 4 | 2.8 s | ✅ |

| Metric | Result |
|---|---|
| Detection rate | 100% (6/6) |
| False-positive rate | 0% |
| Scan latency | 0.8 s – 2.8 s |
| AI recommendation latency | 3–8 s |
| PDF generation | < 1 s |

## 🆚 Comparison with Other Tools

| Feature | ACASE | Burp Suite | OWASP ZAP | securityheaders.com |
|---|---|---|---|---|
| AiTM-specific detection | ✅ | ❌ | ❌ | ❌ |
| Session token entropy | ✅ | Partial | ❌ | ❌ |
| Proxy-layer anomaly detection | ✅ | ❌ | ❌ | ❌ |
| AI-powered recommendations | ✅ | ❌ | ❌ | ❌ |
| Composite risk scoring | ✅ | ❌ | Partial | ❌ |
| Automated PDF report | ✅ | ✅ | ✅ | ❌ |
| Open source / free | ✅ | ❌ | ✅ | N/A |

## 🛡️ STRIDE Mapping

| Threat | AiTM manifestation | ACASE coverage |
|---|---|---|
| Spoofing | Proxy impersonates IdP with cloned cert | Certificate anomaly + redirect-chain analysis |
| Tampering | Cookie modified via relay | Token reflection + reuse analysis |
| Repudiation | Attacker denies using stolen cookie | Timestamp and IP logging |
| Info disclosure | Token exfiltrated silently | Entropy + Secure/HttpOnly checks |
| Denial of service | Token replay flooding | Expiration policy + reuse frequency |
| Elevation of privilege | Full authenticated session takeover | Score ≥ 15 triggers CRITICAL |

## ⚠️ Limitations

- Rule-based; may miss novel AiTM variants (encrypted C2, custom TLS fingerprint evasion)
- Needs direct HTTP endpoint access; cannot assess apps behind authenticated portals
- Lab-scale evaluation (n = 6); production-scale validation is future work

## 🔭 Future Work

- ML-based anomaly detection for novel AiTM variants
- SIEM integration (Splunk, IBM QRadar)
- Cloud SSO support (Azure AD, Okta, Google Workspace)
- Browser extension for passive session-health monitoring
- Docker/Kubernetes one-command deployment
- REST API for CI/CD and DevSecOps pipelines
- Validation across 50+ production web applications

## 👥 Team

| Name | Roll No. |
|---|---|
| V. Divya Sai | Y22CSC058 |
| K. Rajesh | Y22CSC024 |
| G. Rakesh | Y22CSC022 |
| N. Reehana Begum | Y22CSC038 |

**Guide:** J. BhargavaRam, M.Tech, Head of Department

## ⚖️ Ethical Use Disclaimer

ACASE is for **authorised security assessment and education only**. Scan only systems you own or have explicit written permission to test. The authors are not responsible for misuse.

## 📚 Selected References

1. Microsoft, *Digital Defense Report 2023*
2. Group-IB, *0ktapus: Phishing Campaign Targeting 130+ Organisations*, 2022
3. K. Gretzky, *Evilginx2*, GitHub
4. OWASP, *Session Management Cheat Sheet*
5. IETF RFC 6265bis, RFC 6797 (HSTS), RFC 2818

## 📄 License

MIT. See [LICENSE](LICENSE).
