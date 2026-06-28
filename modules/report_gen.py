"""
Module: report_gen.py
Purpose: Generate a structured Markdown pre-engagement intelligence report
"""

import os
from datetime import datetime


def _md_table(headers, rows):
    header_row = "| " + " | ".join(headers) + " |"
    sep_row    = "| " + " | ".join(["---"] * len(headers)) + " |"
    data_rows  = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return f"{header_row}\n{sep_row}\n{data_rows}"


def generate_report(target, results, output_dir, console):
    console.print("\n[*] Generating intelligence report...")

    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"{output_dir}/{target}_{filename_ts}_report.md"
    os.makedirs(output_dir, exist_ok=True)

    lines = []

    # ── Cover ──────────────────────────────────────────────────────────────
    lines += [
        "# Lycoris — Intelligence Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | `{target}` |",
        f"| **Generated** | {timestamp} |",
        "| **Tool** | Lycoris v1.0 |",
        "| **Classification** | CONFIDENTIAL — Authorized Testing Only |",
        "",
        "---",
        "",
        "> ⚠️ **Legal Notice:** This report was generated against a target for which explicit",
        "> written authorization was obtained. Unauthorized use of this tool or reproduction",
        "> of findings against targets without permission is illegal.",
        "",
        "---",
        "",
        "## Table of Contents",
        "",
        "1. [Executive Summary](#1-executive-summary)",
        "2. [WHOIS & Domain Intelligence](#2-whois--domain-intelligence)",
        "3. [DNS Enumeration](#3-dns-enumeration)",
        "4. [Subdomain Enumeration](#4-subdomain-enumeration)",
        "5. [Attack Surface Summary](#5-attack-surface-summary)",
        "6. [Recommended Next Steps](#6-recommended-next-steps)",
        "",
        "---",
        "",
    ]

    # ── 1. Executive Summary ───────────────────────────────────────────────
    lines += [
        "## 1. Executive Summary",
        "",
        f"Passive and active footprinting intelligence gathered against `{target}` "
        f"using Recon Atlas v1.0. Modules executed: `{', '.join(results['meta']['modules_run'])}`.",
        "",
    ]

    whois_data = results.get("whois", {})
    dns_data   = results.get("dns", {})
    sub_data   = results.get("subdomains", {})

    risk_flags = []
    if whois_data.get("domain_age_days") and whois_data["domain_age_days"] < 180:
        risk_flags.append(f"🔴 Domain age < 6 months ({whois_data['domain_age_days']} days)")
    if whois_data.get("privacy_protected"):
        risk_flags.append("🟡 WHOIS privacy protection enabled")

    spf   = dns_data.get("spf_analysis", {})
    dmarc = dns_data.get("dmarc_analysis", {})
    if not spf.get("found"):
        risk_flags.append("🔴 No SPF record — email spoofing possible")
    elif "WEAK" in spf.get("risk","") or "CRITICAL" in spf.get("risk",""):
        risk_flags.append(f"🟡 Weak SPF policy: `{spf.get('all_mechanism')}`")
    if not dmarc.get("found"):
        risk_flags.append("🔴 No DMARC record — phishing emails may reach inboxes")
    elif dmarc.get("policy") == "none":
        risk_flags.append("🟡 DMARC policy = `none` (monitoring only)")

    zt_vuln = [z for z in dns_data.get("zone_transfer", []) if z.get("vulnerable")]
    if zt_vuln:
        risk_flags.append(f"🔴 CRITICAL: Zone transfer succeeded on {', '.join(z['ns'] for z in zt_vuln)}")

    interesting = sub_data.get("interesting_subdomains", [])
    if interesting:
        risk_flags.append(f"🟡 {len(interesting)} high-interest subdomains discovered")

    if risk_flags:
        lines.append("### Key Findings\n")
        for flag in risk_flags:
            lines.append(f"- {flag}")
        lines.append("")
    else:
        lines.append("No critical findings identified in passive footprinting phase.\n")

    lines.append("---\n")

    # ── 2. WHOIS ──────────────────────────────────────────────────────────
    lines += ["## 2. WHOIS & Domain Intelligence", ""]
    if whois_data:
        rows = [
            ["Domain",             whois_data.get("domain", "N/A")],
            ["Registrar",          whois_data.get("registrar", "N/A")],
            ["Registrant Org",     whois_data.get("registrant_org", "N/A")],
            ["Registrant Country", whois_data.get("registrant_country", "N/A")],
            ["Registrant Email",   whois_data.get("registrant_email", "N/A")],
            ["Created",            whois_data.get("created", "N/A")],
            ["Expires",            whois_data.get("expires", "N/A")],
            ["Domain Age",         f"{whois_data.get('domain_age_days', 'N/A')} days"],
            ["Privacy Protected",  "Yes" if whois_data.get("privacy_protected") else "No"],
            ["DNSSEC",             whois_data.get("dnssec", "N/A")],
        ]
        lines.append(_md_table(["Field", "Value"], rows))
        lines.append("")
        if whois_data.get("name_servers"):
            lines.append(f"**Name Servers:** `{'`, `'.join(whois_data['name_servers'])}`\n")
        if whois_data.get("status"):
            lines.append(f"**Domain Status:** `{'`, `'.join(whois_data['status'])}`\n")
    else:
        lines.append("_WHOIS module not executed._\n")
    lines.append("---\n")

    # ── 3. DNS ────────────────────────────────────────────────────────────
    lines += ["## 3. DNS Enumeration", ""]
    if dns_data:
        lines.append("### DNS Records\n")
        dns_rows = []
        for rtype, values in dns_data.get("records", {}).items():
            if values:
                for v in values:
                    dns_rows.append([rtype, v])
            else:
                dns_rows.append([rtype, "_No record_"])
        lines.append(_md_table(["Type", "Value"], dns_rows))
        lines.append("")

        lines.append("### Zone Transfer Results\n")
        zt = dns_data.get("zone_transfer", [])
        if zt:
            for z in zt:
                status = "**🔴 VULNERABLE**" if z.get("vulnerable") else "✅ Refused"
                lines.append(f"- `{z['ns']}` — {status}")
                if z.get("vulnerable") and z.get("records"):
                    lines.append(f"  - {len(z['records'])} zone records exposed")
        else:
            lines.append("_Not attempted or no NS records found._")
        lines.append("")

        lines.append("### Email Security (SPF / DMARC)\n")
        spf_status   = "✅ Found" if spf.get("found") else "🔴 Missing"
        dmarc_status = "✅ Found" if dmarc.get("found") else "🔴 Missing"
        spf_val   = f"`{spf.get('value','N/A')[:60]}`" if spf.get("value") else "N/A"
        dmarc_val = f"`{dmarc.get('value','N/A')[:60]}`" if dmarc.get("value") else "N/A"
        lines += [
            "| Protocol | Status | Value |",
            "|---|---|---|",
            f"| SPF | {spf_status} | {spf_val} |",
            f"| DMARC | {dmarc_status} | {dmarc_val} |",
            "",
        ]
        if spf.get("risk"):
            lines.append(f"> **SPF:** {spf['risk']}\n")
        if dmarc.get("policy"):
            lines.append(f"> **DMARC Policy:** `{dmarc['policy']}`\n")
    else:
        lines.append("_DNS module not executed._\n")
    lines.append("---\n")

    # ── 4. Subdomains ─────────────────────────────────────────────────────
    lines += ["## 4. Subdomain Enumeration", ""]
    if sub_data:
        live  = sub_data.get("live_subdomains", [])
        inter = sub_data.get("interesting_subdomains", [])
        lines += [
            "**Source:** Certificate Transparency Logs (crt.sh) — passive only",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Unique subdomains | {len(sub_data.get('unique_subdomains', []))} |",
            f"| Live hosts | {len(live)} |",
            f"| High-interest targets | {len(inter)} |",
            "",
        ]
        if live:
            lines.append("### Live Subdomains\n")
            live_rows = [[s["subdomain"], ", ".join(s["ips"]), s.get("pattern") or "—"] for s in live]
            lines.append(_md_table(["Subdomain", "IP(s)", "Pattern"], live_rows))
            lines.append("")
        if inter:
            lines.append("### ⚠️ High-Interest Subdomains\n")
            for item in inter:
                lines.append(f"- **`{item['subdomain']}`** ({item.get('pattern')}) — `{', '.join(item['ips'])}`")
            lines.append("")
    else:
        lines.append("_Subdomain module not executed._\n")
    lines.append("---\n")

    # ── 5. Attack Surface ─────────────────────────────────────────────────
    lines += ["## 5. Attack Surface Summary", "", "| Vector | Finding | Risk |", "|---|---|---|"]

    spf_weak   = not spf.get("found") or "WEAK" in spf.get("risk","") or "CRITICAL" in spf.get("risk","")
    dmarc_weak = not dmarc.get("found") or dmarc.get("policy") == "none"

    if spf_weak and dmarc_weak:
        lines.append("| Email Spoofing | No SPF, No DMARC | 🔴 HIGH |")
    elif spf_weak or dmarc_weak:
        lines.append("| Email Spoofing | Partial email controls | 🟡 MEDIUM |")
    else:
        lines.append("| Email Spoofing | SPF + DMARC configured | 🟢 LOW |")

    if zt_vuln:
        lines.append(f"| DNS Zone Transfer | AXFR succeeded on {zt_vuln[0]['ns']} | 🔴 CRITICAL |")
    else:
        lines.append("| DNS Zone Transfer | Refused on all NS | 🟢 LOW |")

    inter = sub_data.get("interesting_subdomains", [])
    live  = sub_data.get("live_subdomains", [])
    if inter:
        lines.append(f"| Subdomain Exposure | {len(inter)} high-interest subdomains live | 🟡 MEDIUM |")
    elif live:
        lines.append(f"| Subdomain Exposure | {len(live)} live subdomains | 🟢 LOW |")

    lines += [
        "",
        "---",
        "",
        "## 6. Recommended Next Steps",
        "",
        f"1. **Web fingerprinting** — Run `whatweb`, `wafw00f` against live subdomains",
        f"2. **Port scanning** — Nmap SYN scan against resolved IPs",
        f"3. **Directory enumeration** — ffuf/gobuster against high-interest subdomains",
        f"4. **Email harvesting** — theHarvester / Hunter.io against `{target}`",
        f"5. **Google dorking** — `site:{target} filetype:pdf OR filetype:env OR intitle:\"index of\"`",
        f"6. **Shodan** — Query discovered IPs for open services and banners",
        "",
        "---",
        "",
        "_Report generated by [Lycoris](https://github.com/18Aswin/lycoris) v1.0_",
        "",
    ]

    with open(report_path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"  [green]✓ Report written[/green]")
    return report_path
