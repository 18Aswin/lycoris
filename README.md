# 🕵️ Lycoris

> **Modular OSINT & Footprinting Framework**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

Lycoris is a Python CLI framework for automated passive and active footprinting. It aggregates WHOIS intelligence, DNS enumeration, certificate transparency‑based subdomain discovery, SSL certificate analysis, HTTP header inspection, and reverse DNS lookups into a structured pre‑engagement intelligence report – the kind a real red team delivers before an engagement begins.

---

## ⚠️ Legal Disclaimer

> Use **only** against targets you own or have **explicit written authorization** to test.  
> Unauthorized use may violate the CFAA, India's IT Act Section 43/66, or equivalent laws in your jurisdiction.  
> The author assumes no liability for misuse.

---

## Features (v1.1)

- **WHOIS Intelligence** — Registrar, registrant, domain age, DNSSEC, privacy detection, RDAP fallback.
- **DNS Enumeration** — Full record set (A, AAAA, MX, NS, TXT, CNAME, SOA), AXFR zone transfer attempt, SPF/DMARC analysis with phishing verdict.
- **Subdomain Discovery** — Passive CT log mining via crt.sh, live DNS resolution, pattern‑based classification (dev/admin/api/staging/vpn/jenkins...).
- **Reverse DNS (PTR)** — Maps discovered IPs back to hostnames, often revealing internal naming schemes.
- **SSL Certificate Analysis** — Issuer, expiry date, and Subject Alternative Names (SANs) – detect expiring certs and hidden subdomains.
- **HTTP Header Inspection** — Server, X‑Powered‑By, Content‑Security‑Policy – fingerprint the web stack and spot missing security headers.
- **HTML Report** — Standalone, self‑contained HTML dashboard with a dark theme, tables, and risk summaries (in addition to Markdown).
- **Progress Bars** — Real‑time feedback during module execution and subdomain resolution.
- **Intelligence Report** — Auto‑generated Markdown and/or HTML pre‑engagement report with attack surface summary.
- **Session Persistence** — Raw JSON saved per run.

---

## Installation

```bash
git clone https://github.com/18Aswin/lycoris.git
cd lycoris
pip install -r requirements.txt

```
## **Usage**

```
# Show help
python lycoris.py -h

# Full scan with Markdown report
python lycoris.py -t example.com -m all -r

# Full scan with HTML report (no Markdown)
python lycoris.py -t example.com -m all --html

# Both Markdown and HTML reports
python lycoris.py -t example.com -m all -r --html

# WHOIS + DNS only
python lycoris.py -t example.com -m whois,dns

# Subdomains only, custom output dir
python lycoris.py -t example.com -m subdomains -o ~/recon
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t / --target` | Target domain | required |
| `-m / --modules` | `whois,dns,subdomains,all` | `all` |
| `-o / --output` | Output directory | `output/` |
| `-r / --report` | Generate Markdown report | off |
| `--html` | Generate HTML report | off |
| `-h / --help` | Show help screen | - |

---

## Project Structure

```
lycoris/
├── lycoris.py              # CLI entry point
├── requirements.txt
├── README.md
├── LICENSE
└── modules/
    ├── __init__.py         # Package Marker
    ├── whois_recon.py      # WHOIS & RDAP intelligence
    ├── dns_recon.py        # DNS enumeration, zone transfer, SPF/DMARC, SSL, headers
    ├── subdomain_enum.py   # CT log subdomain discovery + PTR
    └── report_gen.py       # Markdown & HTML report generator
```


---

## Author

**Aswin** - Ethical Hacker | Security Analyst  
[LinkedIn](https://www.linkedin.com/in/aswin-nair18/)

---

## License

MIT — see [LICENSE](LICENSE)
