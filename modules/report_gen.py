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
        "# Recon Atlas — Intelligence Report",
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

def generate_html_report(target, results, output_dir, console):
    """Generate a standalone HTML report with embedded CSS."""
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

    # Extract key pieces
    spf   = dns_data.get("spf_analysis", {})
    dmarc = dns_data.get("dmarc_analysis", {})

    # Risk flags (same as Markdown report)
    risk_flags = []
    if whois_data.get("domain_age_days") and whois_data["domain_age_days"] < 180:
        risk_flags.append(f"🔴 Domain age < 6 months ({whois_data['domain_age_days']} days)")
    if whois_data.get("privacy_protected"):
        risk_flags.append("🟡 WHOIS privacy protection enabled")

    if not spf.get("found"):
        risk_flags.append("🔴 No SPF record — email spoofing possible")
    elif "WEAK" in spf.get("risk", "") or "CRITICAL" in spf.get("risk", ""):
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

    # HTML template (self-contained)
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
            background: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            padding: 2rem;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2, h3 { color: #f0f6fc; margin-top: 1.5rem; margin-bottom: 0.5rem; }
        h1 { font-size: 2.2rem; border-bottom: 2px solid #30363d; padding-bottom: 0.3rem; }
        h2 { font-size: 1.8rem; border-bottom: 1px solid #30363d; padding-bottom: 0.2rem; }
        h3 { font-size: 1.3rem; color: #8b949e; }
        .badge {
            display: inline-block;
            padding: 0.2rem 0.6rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            margin-right: 0.3rem;
        }
        .badge-green { background: #2ea043; color: #fff; }
        .badge-yellow { background: #d29922; color: #0d1117; }
        .badge-red { background: #da3633; color: #fff; }
        .badge-gray { background: #30363d; color: #8b949e; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            background: #161b22;
            border-radius: 6px;
            overflow: hidden;
        }
        th {
            background: #21262d;
            color: #f0f6fc;
            font-weight: 600;
            padding: 0.5rem 0.8rem;
            text-align: left;
        }
        td {
            padding: 0.4rem 0.8rem;
            border-bottom: 1px solid #30363d;
        }
        tr:last-child td { border-bottom: none; }
        .risk-high { color: #f85149; font-weight: bold; }
        .risk-medium { color: #d29922; font-weight: bold; }
        .risk-low { color: #3fb950; font-weight: bold; }
        .note {
            background: #21262d;
            border-left: 4px solid #d29922;
            padding: 0.8rem 1.2rem;
            margin: 1rem 0;
            border-radius: 4px;
        }
        .note-critical { border-left-color: #f85149; }
        .note-good { border-left-color: #3fb950; }
        .footer {
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #30363d;
            color: #8b949e;
            font-size: 0.9rem;
            text-align: center;
        }
        .subdomain-flag {
            color: #d29922;
            font-weight: bold;
        }
        .code { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; background: #0d1117; padding: 0.1rem 0.4rem; border-radius: 4px; }
        @media (max-width: 600px) {
            body { padding: 1rem; }
            table, th, td { font-size: 0.8rem; }
        }
    </style>
</head>
<body>
<div class="container">

    <h1>🕵️ Lycoris – Intelligence Report</h1>
    <p><strong>Target:</strong> {{ target }}<br>
    <strong>Generated:</strong> {{ timestamp }}<br>
    <strong>Tool:</strong> Lycoris v1.0<br>
    <strong>Modules:</strong> {{ modules_run }}</p>

    <div class="note note-critical">
        <strong>⚠️ Legal Notice:</strong> This report was generated against a target for which explicit written authorization was obtained. Unauthorized use is illegal.
    </div>

    <hr style="border: 1px solid #30363d; margin: 2rem 0;">

    <!-- ========== 1. Executive Summary ========== -->
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
        <p>✅ No critical findings identified.</p>
    {% endif %}

    <hr>

    <!-- ========== 2. WHOIS ========== -->
    <h2>2. WHOIS &amp; Domain Intelligence</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Domain</td><td>{{ whois.get('domain', 'N/A') }}</td></tr>
        <tr><td>Registrar</td><td>{{ whois.get('registrar', 'N/A') }}</td></tr>
        <tr><td>Registrant Org</td><td>{{ whois.get('registrant_org', 'N/A') }}</td></tr>
        <tr><td>Registrant Country</td><td>{{ whois.get('registrant_country', 'N/A') }}</td></tr>
        <tr><td>Created</td><td>{{ whois.get('created', 'N/A') }}</td></tr>
        <tr><td>Expires</td><td>{{ whois.get('expires', 'N/A') }}</td></tr>
        <tr><td>Domain Age</td><td>{{ whois.get('domain_age_days', 'N/A') }} days</td></tr>
        <tr><td>Privacy Protected</td><td>{% if whois.get('privacy_protected') %}✅ Yes{% else %}❌ No{% endif %}</td></tr>
        <tr><td>DNSSEC</td><td>{{ whois.get('dnssec', 'N/A') }}</td></tr>
        <tr><td>Name Servers</td><td>{% for ns in whois.get('name_servers', []) %}<code>{{ ns }}</code> {% endfor %}</td></tr>
    </table>

    <hr>

    <!-- ========== 3. DNS ========== -->
    <h2>3. DNS Enumeration</h2>

    <h3>DNS Records</h3>
    <table>
        <tr><th>Type</th><th>Value</th></tr>
        {% for rtype, values in records.items() %}
            {% if values %}
                {% for val in values %}
                    <tr><td>{{ rtype }}</td><td><code>{{ val }}</code></td></tr>
                {% endfor %}
            {% else %}
                <tr><td>{{ rtype }}</td><td><em>No record</em></td></tr>
            {% endif %}
        {% endfor %}
    </table>

    <h3>Zone Transfer Results</h3>
    <ul>
    {% for z in zone_transfer %}
        <li><code>{{ z.ns }}</code> — {% if z.vulnerable %}<span class="risk-high">🔴 VULNERABLE</span>{% else %}✅ Refused{% endif %}</li>
    {% else %}
        <li><em>Not attempted or no NS records found.</em></li>
    {% endfor %}
    </ul>

    <h3>Email Security (SPF / DMARC)</h3>
    <table>
        <tr><th>Protocol</th><th>Status</th><th>Value</th></tr>
        <tr>
            <td>SPF</td>
            <td>{% if spf.get('found') %}✅ Found{% else %}🔴 Missing{% endif %}</td>
            <td><code>{{ spf.get('value', 'N/A') }}</code></td>
        </tr>
        <tr>
            <td>DMARC</td>
            <td>{% if dmarc.get('found') %}✅ Found{% else %}🔴 Missing{% endif %}</td>
            <td><code>{{ dmarc.get('value', 'N/A') }}</code></td>
        </tr>
    </table>
    {% if spf.get('risk') %}
        <p><strong>SPF:</strong> {{ spf['risk'] }}</p>
    {% endif %}
    {% if dmarc.get('policy') %}
        <p><strong>DMARC Policy:</strong> <code>{{ dmarc['policy'] }}</code></p>
    {% endif %}

    <!-- SSL -->
    {% if ssl_info %}
        <h3>SSL Certificate</h3>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Issuer</td><td>{{ ssl_info.get('issuer', {}).get('organizationName', ['Unknown'])[0] }}</td></tr>
            <tr><td>Expiry</td><td>{{ ssl_info.get('expiry', 'N/A') }}</td></tr>
            <tr><td>Subject Alternative Names</td><td>{{ ssl_info.get('san', []) | join(', ') or 'None' }}</td></tr>
        </table>
    {% endif %}

    <!-- HTTP Headers -->
    {% if http_headers %}
        <h3>HTTP Headers</h3>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Scheme</td><td>{{ http_headers.get('scheme', 'N/A') }}</td></tr>
            <tr><td>Status Code</td><td>{{ http_headers.get('status_code', 'N/A') }}</td></tr>
            <tr><td>Server</td><td>{{ http_headers.get('server', 'N/A') }}</td></tr>
            <tr><td>X-Powered-By</td><td>{{ http_headers.get('x_powered_by', 'N/A') }}</td></tr>
            <tr><td>Content-Security-Policy</td><td><code>{{ http_headers.get('csp', 'None')[:100] }}{% if http_headers.get('csp')|length > 100 %}...{% endif %}</code></td></tr>
        </table>
    {% endif %}

    <hr>

    <!-- ========== 4. Subdomains ========== -->
    <h2>4. Subdomain Enumeration</h2>
    <p><strong>Source:</strong> Certificate Transparency logs (crt.sh) – passive only.</p>
    <table>
        <tr><th>Metric</th><th>Count</th></tr>
        <tr><td>Unique subdomains</td><td>{{ unique_subdomains|length }}</td></tr>
        <tr><td>Live hosts</td><td>{{ live_subdomains|length }}</td></tr>
        <tr><td>High-interest targets</td><td>{{ interesting_subdomains|length }}</td></tr>
    </table>

    {% if live_subdomains %}
        <h3>Live Subdomains</h3>
        <table>
            <tr><th>Subdomain</th><th>IP(s)</th><th>PTR</th><th>Pattern</th></tr>
            {% for item in live_subdomains %}
                <tr>
                    <td><code>{{ item.subdomain }}</code></td>
                    <td><code>{{ item.ips | join(', ') }}</code></td>
                    <td>{{ item.get('ptrs', []) | join(', ') or '—' }}</td>
                    <td>{% if item.pattern %}<span class="subdomain-flag">⚠ {{ item.pattern }}</span>{% else %}—{% endif %}</td>
                </tr>
            {% endfor %}
        </table>
    {% endif %}

    {% if interesting_subdomains %}
        <h3>⚠️ High-Interest Subdomains</h3>
        <ul>
        {% for item in interesting_subdomains %}
            <li><code>{{ item.subdomain }}</code> ({{ item.pattern }}) — IP: {{ item.ips | join(', ') }} — PTR: {{ item.get('ptrs', []) | join(', ') or '—' }}</li>
        {% endfor %}
        </ul>
    {% endif %}

    <hr>

    <!-- ========== 5. Attack Surface ========== -->
    <h2>5. Attack Surface Summary</h2>
    <table>
        <tr><th>Vector</th><th>Finding</th><th>Risk</th></tr>
        <tr>
            <td>Email Spoofing</td>
            <td>{% if spf.get('found') and dmarc.get('found') %}SPF + DMARC configured{% else %}Partial or missing controls{% endif %}</td>
            <td>
                {% if spf.get('found') and dmarc.get('found') and dmarc.get('policy') == 'reject' %}
                    <span class="risk-low">🟢 LOW</span>
                {% elif spf.get('found') and dmarc.get('found') %}
                    <span class="risk-medium">🟡 MEDIUM</span>
                {% else %}
                    <span class="risk-high">🔴 HIGH</span>
                {% endif %}
            </td>
        </tr>
        <tr>
            <td>DNS Zone Transfer</td>
            <td>{% if zt_vuln %}AXFR succeeded on {{ zt_vuln[0].ns }}{% else %}Refused on all NS{% endif %}</td>
            <td>{% if zt_vuln %}<span class="risk-high">🔴 CRITICAL</span>{% else %}<span class="risk-low">🟢 LOW</span>{% endif %}</td>
        </tr>
        <tr>
            <td>Subdomain Exposure</td>
            <td>{{ interesting_subdomains|length }} high-interest subdomains live</td>
            <td>{% if interesting_subdomains|length > 0 %}<span class="risk-medium">🟡 MEDIUM</span>{% else %}<span class="risk-low">🟢 LOW</span>{% endif %}</td>
        </tr>
        {% if ssl_info %}
            <tr>
                <td>SSL Certificate Expiry</td>
                <td>
                    {% set expiry_str = ssl_info.get('expiry', '') %}
                    {% if expiry_str %}
                        {% set days_left = 0 %}
                        {# We cannot do arithmetic in Jinja, but we can just show the expiry #}
                        Expires on {{ expiry_str }}
                    {% else %}N/A{% endif %}
                </td>
                <td>
                    {# We'll just show a static note, but we can compute if we pass days_left #}
                    <span class="badge badge-gray">See full certificate</span>
                </td>
            </tr>
        {% endif %}
    </table>

    <hr>

    <!-- ========== 6. Recommendations ========== -->
    <h2>6. Recommended Next Steps</h2>
    <ol>
        <li><strong>Web fingerprinting</strong> — Run <code>whatweb</code>, <code>wafw00f</code> against live subdomains.</li>
        <li><strong>Port scanning</strong> — Nmap SYN scan against resolved IPs.</li>
        <li><strong>Directory enumeration</strong> — <code>ffuf</code> / <code>gobuster</code> against high-interest subdomains.</li>
        <li><strong>Email harvesting</strong> — theHarvester / Hunter.io against <code>{{ target }}</code>.</li>
        <li><strong>Google dorking</strong> — <code>site:{{ target }} filetype:pdf OR filetype:env OR intitle:"index of"</code></li>
        <li><strong>Shodan</strong> — Query discovered IPs for open services and banners.</li>
    </ol>

    <div class="footer">
        Report generated by <a href="https://github.com/18Aswin/lycoris" style="color: #58a6ff;">Lycoris</a> v1.0
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
