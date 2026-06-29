"""
Purpose: Generate structured Markdown and HTML intelligence reports
"""

import os
from datetime import datetime


def _md_table(headers, rows):
    header_row = "| " + " | ".join(headers) + " |"
    sep_row    = "| " + " | ".join(["---"] * len(headers)) + " |"
    data_rows  = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return f"{header_row}\n{sep_row}\n{data_rows}"


def generate_report(target, results, output_dir, console):
    """Generate Markdown intelligence report (original)."""
    console.print("\n[*] Generating intelligence report...")

    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"{output_dir}/{target}_{filename_ts}_report.md"
    os.makedirs(output_dir, exist_ok=True)

    lines = []

    # ── Cover ──────────────────────────────────────────────────────────────
    lines += [
        "# Recon Atlas — Intelligence Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Target** | `{target}` |",
        f"| **Generated** | {timestamp} |",
        "| **Tool** | Lycoris v1.1 |",
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
        f"using Lycoris v1.1. Modules executed: `{', '.join(results['meta']['modules_run'])}`.",
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

        # ── New: SSL Certificate ──────────────────────────────────────────
        ssl_info = dns_data.get("ssl_info")
        if ssl_info:
            lines.append("### SSL Certificate\n")
            issuer = ssl_info.get("issuer", {})
            issuer_org = issuer.get("organizationName", ["Unknown"])[0] if issuer.get("organizationName") else "Unknown"
            expiry = ssl_info.get("expiry", "N/A")
            san = ssl_info.get("san", [])
            san_str = ", ".join(san[:10]) + (" ..." if len(san) > 10 else "")
            lines.append(_md_table(
                ["Field", "Value"],
                [
                    ["Issuer", issuer_org],
                    ["Expiry", expiry],
                    ["Subject Alternative Names", san_str or "None"]
                ]
            ))
            lines.append("")

        # ── New: HTTP Headers ─────────────────────────────────────────────
        headers_info = dns_data.get("http_headers")
        if headers_info:
            lines.append("### HTTP Headers\n")
            lines.append(_md_table(
                ["Field", "Value"],
                [
                    ["Scheme", headers_info.get("scheme", "N/A")],
                    ["Status Code", headers_info.get("status_code", "N/A")],
                    ["Server", headers_info.get("server", "N/A")],
                    ["X-Powered-By", headers_info.get("x_powered_by", "N/A")],
                    ["Content-Security-Policy", headers_info.get("csp", "None")[:100] + ("..." if len(headers_info.get("csp", "")) > 100 else "")]
                ]
            ))
            lines.append("")
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
            live_rows = []
            for item in live:
                ptr_str = ", ".join(item.get("ptrs", [])) or "—"
                live_rows.append([item["subdomain"], ", ".join(item["ips"]), ptr_str, item.get("pattern") or "—"])
            lines.append(_md_table(["Subdomain", "IP(s)", "PTR", "Pattern"], live_rows))
            lines.append("")
        if inter:
            lines.append("### ⚠️ High-Interest Subdomains\n")
            for item in inter:
                ptr_str = ", ".join(item.get("ptrs", [])) or "—"
                lines.append(f"- **`{item['subdomain']}`** ({item.get('pattern')}) — `{', '.join(item['ips'])}` (PTR: {ptr_str})")
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

    # SSL & Headers can add additional risk indicators
    ssl_info = dns_data.get("ssl_info")
    if ssl_info:
        expiry_str = ssl_info.get("expiry", "")
        if expiry_str:
            try:
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_date - datetime.now()).days
                if days_left < 30:
                    lines.append(f"| SSL Certificate | Expires in {days_left} days | 🟡 MEDIUM |")
                else:
                    lines.append(f"| SSL Certificate | Valid ({days_left} days left) | 🟢 LOW |")
            except:
                pass

    headers_info = dns_data.get("http_headers")
    if headers_info:
        csp = headers_info.get("csp", "")
        if not csp or "default-src" not in csp:
            lines.append("| Content-Security-Policy | Missing or weak CSP | 🟡 MEDIUM |")
        else:
            lines.append("| Content-Security-Policy | Present | 🟢 LOW |")

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
        "_Report generated by [Lycoris](https://github.com/18Aswin/lycoris) v1.1_",
        "",
    ]

    with open(report_path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"  [green]✓ Report written[/green]")
    return report_path


def generate_html_report(target, results, output_dir, console):
    """
    Generate a standalone, professional HTML report with embedded CSS.
    Designed for clarity and enterprise use – minimal emojis, clean typography.
    """
    console.print("\n[*] Generating HTML report...")

    from jinja2 import Template
    import json
    from datetime import datetime

    filename_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"{output_dir}/{target}_{filename_ts}_report.html"
    os.makedirs(output_dir, exist_ok=True)

    # Prepare data for the template
    whois_data = results.get("whois", {})
    dns_data   = results.get("dns", {})
    sub_data   = results.get("subdomains", {})

    spf   = dns_data.get("spf_analysis", {})
    dmarc = dns_data.get("dmarc_analysis", {})

    # Risk flags (same as Markdown report)
    risk_flags = []
    if whois_data.get("domain_age_days") and whois_data["domain_age_days"] < 180:
        risk_flags.append(f"Domain age < 6 months ({whois_data['domain_age_days']} days)")
    if whois_data.get("privacy_protected"):
        risk_flags.append("WHOIS privacy protection enabled")

    if not spf.get("found"):
        risk_flags.append("No SPF record — email spoofing possible")
    elif "WEAK" in spf.get("risk", "") or "CRITICAL" in spf.get("risk", ""):
        risk_flags.append(f"Weak SPF policy: `{spf.get('all_mechanism')}`")
    if not dmarc.get("found"):
        risk_flags.append("No DMARC record — phishing emails may reach inboxes")
    elif dmarc.get("policy") == "none":
        risk_flags.append("DMARC policy = `none` (monitoring only)")

    zt_vuln = [z for z in dns_data.get("zone_transfer", []) if z.get("vulnerable")]
    if zt_vuln:
        risk_flags.append(f"CRITICAL: Zone transfer succeeded on {', '.join(z['ns'] for z in zt_vuln)}")

    interesting = sub_data.get("interesting_subdomains", [])
    if interesting:
        risk_flags.append(f"{len(interesting)} high-interest subdomains discovered")

    # Build context for Jinja2
    context = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules_run": ", ".join(results['meta']['modules_run']),
        "whois": whois_data,
        "dns": dns_data,
        "subdomains": sub_data,
        "spf": spf,
        "dmarc": dmarc,
        "risk_flags": risk_flags,
        "zt_vuln": zt_vuln,
        "interesting_subdomains": interesting,
        "live_subdomains": sub_data.get("live_subdomains", []),
        "unique_subdomains": sub_data.get("unique_subdomains", []),
        "ssl_info": dns_data.get("ssl_info"),
        "http_headers": dns_data.get("http_headers"),
        "zone_transfer": dns_data.get("zone_transfer", []),
        "records": dns_data.get("records", {}),
    }

    # Professional, minimal HTML template
    template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Lycoris Recon Report – {{ target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #f8f9fa;
            color: #212529;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            padding: 2rem;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #ffffff;
            padding: 2.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        h1, h2, h3, h4 {
            color: #1a1a1a;
            margin-top: 1.8rem;
            margin-bottom: 0.8rem;
            font-weight: 600;
            letter-spacing: -0.02em;
        }
        h1 {
            font-size: 2.2rem;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 0.5rem;
            margin-top: 0;
        }
        h2 {
            font-size: 1.8rem;
            border-bottom: 1px solid #e9ecef;
            padding-bottom: 0.3rem;
        }
        h3 {
            font-size: 1.4rem;
            color: #343a40;
        }
        h4 {
            font-size: 1.1rem;
            color: #495057;
            margin-top: 1.2rem;
        }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-low { background: #d4edda; color: #155724; }
        .badge-medium { background: #fff3cd; color: #856404; }
        .badge-high { background: #f8d7da; color: #721c24; }
        .badge-critical { background: #dc3545; color: #fff; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            font-size: 0.95rem;
            table-layout: fixed;    /* enforce column widths */
        }
        th {
            background: #f1f3f5;
            color: #1a1a1a;
            font-weight: 600;
            padding: 0.6rem 0.8rem;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 0.5rem 0.8rem;
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
            word-break: break-word;  /* wrap long values */
            max-width: 400px;        /* prevent overflow */
        }
        tr:last-child td { border-bottom: none; }
        .risk-high { color: #dc3545; font-weight: 600; }
        .risk-medium { color: #fd7e14; font-weight: 600; }
        .risk-low { color: #28a745; font-weight: 600; }
        .risk-critical { color: #dc3545; font-weight: 700; }
        .note {
            background: #f8f9fa;
            border-left: 4px solid #6c757d;
            padding: 0.8rem 1.2rem;
            margin: 1rem 0;
            border-radius: 4px;
        }
        .note-warning {
            border-left-color: #ffc107;
            background: #fff3cd;
        }
        .note-danger {
            border-left-color: #dc3545;
            background: #f8d7da;
        }
        .note-success {
            border-left-color: #28a745;
            background: #d4edda;
        }
        .code {
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
            background: #f1f3f5;
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-size: 0.9rem;
            word-break: break-all;   /* ensure long strings wrap */
            white-space: pre-wrap;   /* preserve spaces but wrap */
        }
        .footer {
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #e9ecef;
            color: #6c757d;
            font-size: 0.9rem;
            text-align: center;
        }
        .subdomain-flag {
            color: #856404;
            font-weight: 600;
        }
        ul, ol {
            padding-left: 1.5rem;
            margin: 0.5rem 0;
        }
        li { margin: 0.3rem 0; }
        .section-divider {
            margin: 2.5rem 0;
            border: 0;
            border-top: 1px solid #e9ecef;
        }
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem 1rem;
            margin: 1rem 0;
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 6px;
        }
        .meta-item {
            display: flex;
            flex-wrap: wrap;
        }
        .meta-item strong {
            min-width: 120px;
            color: #495057;
        }
        .meta-item span {
            font-weight: 500;
        }
        /* Ensure code blocks inside table cells wrap */
        td .code {
            word-break: break-all;
            white-space: pre-wrap;
        }
        @media (max-width: 600px) {
            body { padding: 1rem; }
            .container { padding: 1.5rem; }
            table, th, td { font-size: 0.8rem; }
            .meta-grid { grid-template-columns: 1fr; }
        }
        /* Print styles */
        @media print {
            body { background: #fff; padding: 0.5rem; }
            .container { box-shadow: none; padding: 1rem; }
        }
    </style>
</head>
<body>
<div class="container">

    <h1>Lycoris Reconnaissance Report</h1>
    <div class="meta-grid">
        <div class="meta-item"><strong>Target</strong><span>{{ target }}</span></div>
        <div class="meta-item"><strong>Generated</strong><span>{{ timestamp }}</span></div>
        <div class="meta-item"><strong>Tool</strong><span>Lycoris v1.1</span></div>
        <div class="meta-item"><strong>Modules</strong><span>{{ modules_run }}</span></div>
    </div>

    <div class="note note-warning">
        <strong>Legal Notice:</strong> This report was generated against a target for which explicit written authorization was obtained. Unauthorised use is prohibited.
    </div>

    <hr class="section-divider">

    <!-- 1. Executive Summary -->
    <h2>1. Executive Summary</h2>
    <p>Passive and active footprinting intelligence gathered against <code>{{ target }}</code>.</p>
    {% if risk_flags %}
        <h3>Key Findings</h3>
        <ul>
        {% for flag in risk_flags %}
            <li>{{ flag }}</li>
        {% endfor %}
        </ul>
    {% else %}
        <p><span class="badge badge-low">No critical findings</span></p>
    {% endif %}

    <hr class="section-divider">

    <!-- 2. WHOIS -->
    <h2>2. WHOIS &amp; Domain Intelligence</h2>
    <table>
        <colgroup>
            <col style="width:30%">
            <col style="width:70%">
        </colgroup>
        <thead><tr><th>Field</th><th>Value</th></tr></thead>
        <tbody>
            <tr><td>Domain</td><td>{{ whois.get('domain', 'N/A') }}</td></tr>
            <tr><td>Registrar</td><td>{{ whois.get('registrar', 'N/A') }}</td></tr>
            <tr><td>Registrant Org</td><td>{{ whois.get('registrant_org', 'N/A') }}</td></tr>
            <tr><td>Registrant Country</td><td>{{ whois.get('registrant_country', 'N/A') }}</td></tr>
            <tr><td>Created</td><td>{{ whois.get('created', 'N/A') }}</td></tr>
            <tr><td>Expires</td><td>{{ whois.get('expires', 'N/A') }}</td></tr>
            <tr><td>Domain Age</td><td>{{ whois.get('domain_age_days', 'N/A') }} days</td></tr>
            <tr><td>Privacy Protected</td><td>{% if whois.get('privacy_protected') %}Yes{% else %}No{% endif %}</td></tr>
            <tr><td>DNSSEC</td><td>{{ whois.get('dnssec', 'N/A') }}</td></tr>
            <tr><td>Name Servers</td><td>{% for ns in whois.get('name_servers', []) %}<span class="code">{{ ns }}</span> {% endfor %}</td></tr>
        </tbody>
    </table>

    <hr class="section-divider">

    <!-- 3. DNS -->
    <h2>3. DNS Enumeration</h2>

    <h3>3.1 Records</h3>
    <table>
        <colgroup>
            <col style="width:20%">
            <col style="width:80%">
        </colgroup>
        <thead><tr><th>Type</th><th>Value</th></tr></thead>
        <tbody>
        {% for rtype, values in records.items() %}
            {% if values %}
                {% for val in values %}
                    <tr><td>{{ rtype }}</td><td><span class="code">{{ val }}</span></td></tr>
                {% endfor %}
            {% else %}
                <tr><td>{{ rtype }}</td><td><em>No record</em></td></tr>
            {% endif %}
        {% endfor %}
        </tbody>
    </table>

    <h3>3.2 Zone Transfer</h3>
    <ul>
    {% for z in zone_transfer %}
        <li><span class="code">{{ z.ns }}</span> — {% if z.vulnerable %}<span class="risk-critical">VULNERABLE</span>{% else %}Refused (secure){% endif %}</li>
    {% else %}
        <li><em>Not attempted or no NS records.</em></li>
    {% endfor %}
    </ul>

    <h3>3.3 Email Security (SPF / DMARC)</h3>
    <table>
        <colgroup>
            <col style="width:20%">
            <col style="width:20%">
            <col style="width:60%">
        </colgroup>
        <thead><tr><th>Protocol</th><th>Status</th><th>Value</th></tr></thead>
        <tbody>
            <tr>
                <td>SPF</td>
                <td>{% if spf.get('found') %}<span class="badge badge-low">Found</span>{% else %}<span class="badge badge-high">Missing</span>{% endif %}</td>
                <td><span class="code">{{ spf.get('value', 'N/A') }}</span></td>
            </tr>
            <tr>
                <td>DMARC</td>
                <td>{% if dmarc.get('found') %}<span class="badge badge-low">Found</span>{% else %}<span class="badge badge-high">Missing</span>{% endif %}</td>
                <td><span class="code">{{ dmarc.get('value', 'N/A') }}</span></td>
            </tr>
        </tbody>
    </table>
    {% if spf.get('risk') %}
        <div class="note note-{% if 'CRITICAL' in spf['risk'] %}danger{% elif 'WEAK' in spf['risk'] %}warning{% else %}success{% endif %}">
            <strong>SPF:</strong> {{ spf['risk'] }}
        </div>
    {% endif %}
    {% if dmarc.get('policy') %}
        <div class="note note-success">
            <strong>DMARC Policy:</strong> <span class="code">{{ dmarc['policy'] }}</span>
        </div>
    {% endif %}

    {% if ssl_info %}
        <h3>3.4 SSL Certificate</h3>
        <table>
            <colgroup>
                <col style="width:30%">
                <col style="width:70%">
            </colgroup>
            <thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>
                <tr><td>Issuer</td><td>{{ ssl_info.get('issuer', {}).get('organizationName', ['Unknown'])[0] }}</td></tr>
                <tr><td>Expiry</td><td>{{ ssl_info.get('expiry', 'N/A') }}</td></tr>
                <tr><td>Subject Alternative Names</td><td><span class="code">{{ ssl_info.get('san', []) | join(', ') or 'None' }}</span></td></tr>
            </tbody>
        </table>
    {% endif %}

    {% if http_headers %}
        <h3>3.5 HTTP Headers</h3>
        <table>
            <colgroup>
                <col style="width:25%">
                <col style="width:75%">
            </colgroup>
            <thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>
                <tr><td>Scheme</td><td>{{ http_headers.get('scheme', 'N/A') }}</td></tr>
                <tr><td>Status Code</td><td>{{ http_headers.get('status_code', 'N/A') }}</td></tr>
                <tr><td>Server</td><td>{{ http_headers.get('server', 'N/A') }}</td></tr>
                <tr><td>X-Powered-By</td><td>{{ http_headers.get('x_powered_by', 'N/A') }}</td></tr>
                <tr><td>Content-Security-Policy</td><td><span class="code">{{ http_headers.get('csp', 'None') }}</span></td></tr>
            </tbody>
        </table>
    {% endif %}

    <hr class="section-divider">

    <!-- 4. Subdomains -->
    <h2>4. Subdomain Enumeration</h2>
    <p><strong>Source:</strong> Certificate Transparency logs (passive).</p>
    <table>
        <colgroup>
            <col style="width:50%">
            <col style="width:50%">
        </colgroup>
        <thead><tr><th>Metric</th><th>Count</th></tr></thead>
        <tbody>
            <tr><td>Unique subdomains</td><td>{{ unique_subdomains|length }}</td></tr>
            <tr><td>Live hosts</td><td>{{ live_subdomains|length }}</td></tr>
            <tr><td>High-interest targets</td><td>{{ interesting_subdomains|length }}</td></tr>
        </tbody>
    </table>

    {% if live_subdomains %}
        <h3>Live Subdomains</h3>
        <table>
            <colgroup>
                <col style="width:25%">
                <col style="width:25%">
                <col style="width:25%">
                <col style="width:25%">
            </colgroup>
            <thead><tr><th>Subdomain</th><th>IP(s)</th><th>PTR</th><th>Pattern</th></tr></thead>
            <tbody>
            {% for item in live_subdomains %}
                <tr>
                    <td><span class="code">{{ item.subdomain }}</span></td>
                    <td><span class="code">{{ item.ips | join(', ') }}</span></td>
                    <td>{{ item.get('ptrs', []) | join(', ') or '—' }}</td>
                    <td>{% if item.pattern %}<span class="subdomain-flag">{{ item.pattern }}</span>{% else %}—{% endif %}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    {% endif %}

    {% if interesting_subdomains %}
        <h3>High‑Interest Subdomains</h3>
        <ul>
        {% for item in interesting_subdomains %}
            <li><span class="code">{{ item.subdomain }}</span> ({{ item.pattern }}) — IP: {{ item.ips | join(', ') }} — PTR: {{ item.get('ptrs', []) | join(', ') or '—' }}</li>
        {% endfor %}
        </ul>
    {% endif %}

    <hr class="section-divider">

    <!-- 5. Attack Surface -->
    <h2>5. Attack Surface Summary</h2>
    <table>
        <colgroup>
            <col style="width:25%">
            <col style="width:50%">
            <col style="width:25%">
        </colgroup>
        <thead><tr><th>Vector</th><th>Finding</th><th>Risk</th></tr></thead>
        <tbody>
            <tr>
                <td>Email Spoofing</td>
                <td>{% if spf.get('found') and dmarc.get('found') %}SPF + DMARC configured{% else %}Partial or missing controls{% endif %}</td>
                <td>
                    {% if spf.get('found') and dmarc.get('found') and dmarc.get('policy') == 'reject' %}
                        <span class="risk-low">Low</span>
                    {% elif spf.get('found') and dmarc.get('found') %}
                        <span class="risk-medium">Medium</span>
                    {% else %}
                        <span class="risk-high">High</span>
                    {% endif %}
                </td>
            </tr>
            <tr>
                <td>DNS Zone Transfer</td>
                <td>{% if zt_vuln %}AXFR succeeded on {{ zt_vuln[0].ns }}{% else %}Refused on all NS{% endif %}</td>
                <td>{% if zt_vuln %}<span class="risk-critical">Critical</span>{% else %}<span class="risk-low">Low</span>{% endif %}</td>
            </tr>
            <tr>
                <td>Subdomain Exposure</td>
                <td>{{ interesting_subdomains|length }} high‑interest subdomains live</td>
                <td>{% if interesting_subdomains|length > 0 %}<span class="risk-medium">Medium</span>{% else %}<span class="risk-low">Low</span>{% endif %}</td>
            </tr>
            {% if ssl_info %}
            <tr>
                <td>SSL Certificate</td>
                <td>
                    {% set expiry_str = ssl_info.get('expiry', '') %}
                    {% if expiry_str %}
                        Expires on {{ expiry_str }}
                    {% else %}N/A{% endif %}
                </td>
                <td>
                    <span class="badge badge-low">Valid (check expiry)</span>
                </td>
            </tr>
            {% endif %}
            {% if http_headers %}
            <tr>
                <td>Content-Security-Policy</td>
                <td>{% if http_headers.get('csp', '') %}Present{% else %}Missing or weak{% endif %}</td>
                <td>{% if http_headers.get('csp', '') %}<span class="risk-low">Low</span>{% else %}<span class="risk-medium">Medium</span>{% endif %}</td>
            </tr>
            {% endif %}
        </tbody>
    </table>

    <hr class="section-divider">

    <!-- 6. Recommendations -->
    <h2>6. Recommended Next Steps</h2>
    <ol>
        <li><strong>Web fingerprinting</strong> — Run <span class="code">whatweb</span>, <span class="code">wafw00f</span> against live subdomains.</li>
        <li><strong>Port scanning</strong> — Nmap SYN scan against resolved IPs.</li>
        <li><strong>Directory enumeration</strong> — <span class="code">ffuf</span> / <span class="code">gobuster</span> against high‑interest subdomains.</li>
        <li><strong>Email harvesting</strong> — theHarvester / Hunter.io against <span class="code">{{ target }}</span>.</li>
        <li><strong>Google dorking</strong> — <span class="code">site:{{ target }} filetype:pdf OR filetype:env OR intitle:"index of"</span></li>
        <li><strong>Shodan</strong> — Query discovered IPs for open services and banners.</li>
    </ol>

    <div class="footer">
        Report generated by <a href="https://github.com/18Aswin/lycoris" style="color: #007bff; text-decoration: none;">Lycoris</a> v1.1
    </div>

</div>
</body>
</html>
    """

    template = Template(template_str)
    html_content = template.render(**context)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"  [green]✓ HTML report generated[/green]")
    return report_path
