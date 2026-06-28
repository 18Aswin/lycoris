# 🕵️ Lycoris

> **Modular OSINT & Footprinting Framework**

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-brightgreen)]()

Lycoris is a Python CLI framework for automated passive and active footprinting. It aggregates WHOIS intelligence, DNS enumeration, and certificate transparency-based subdomain discovery into a structured pre-engagement intelligence report — the kind a real red team delivers before an engagement begins.

---

## ⚠️ Legal Disclaimer

> Use **only** against targets you own or have **explicit written authorization** to test.  
> Unauthorized use may violate the CFAA, India's IT Act Section 43/66, or equivalent laws in your jurisdiction.  
> The author assumes no liability for misuse.

---

## Features

- **WHOIS Intelligence** — Registrar, registrant, domain age, DNSSEC, privacy detection, RDAP fallback
- **DNS Enumeration** — Full record set (A, AAAA, MX, NS, TXT, CNAME, SOA), AXFR zone transfer attempt, SPF/DMARC analysis with phishing verdict
- **Subdomain Discovery** — Passive CT log mining via crt.sh, live DNS resolution, pattern-based classification (dev/admin/api/staging/vpn/jenkins...)
- **Intelligence Report** — Auto-generated Markdown pre-engagement report with attack surface summary
- **Session Persistence** — Raw JSON saved per run

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
python lycoris.py

# Full scan with report
python lycoris.py -t example.com -m all -r

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

---

## Project Structure

```
lycoris/
├── lycoris.py              # CLI entry point
├── requirements.txt
├── README.md
├── LICENSE
└── modules/
    ├── whois_recon.py      # WHOIS & RDAP intelligence
    ├── dns_recon.py        # DNS enumeration + zone transfer + SPF/DMARC
    ├── subdomain_enum.py   # CT log subdomain discovery
    └── report_gen.py       # Markdown report generator
```


---

## Author

**Aswin** — Security Analyst | VAPT  
[LinkedIn](https://www.linkedin.com/in/aswin-nair18/)

---

## License

MIT — see [LICENSE](LICENSE)
