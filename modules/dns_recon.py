"""
Module: dns_recon.py
Purpose: Comprehensive DNS record enumeration and analysis

Techniques:
  - A / AAAA record lookup
  - MX record lookup (mail server discovery)
  - NS record lookup (authoritative name servers)
  - TXT record lookup (SPF, DKIM, DMARC, verification tokens)
  - CNAME record lookup (alias chain / infrastructure fingerprinting)
  - SOA record lookup (zone admin contact)
  - Zone Transfer attempt (AXFR — misconfiguration check)
  - SPF policy analysis (email spoofing risk)
  - DMARC policy analysis (phishing protection assessment)
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
from rich.table import Table
from rich import box
from rich.panel import Panel


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _resolve(domain, rtype, resolver):
    try:
        answers = resolver.resolve(domain, rtype, lifetime=8)
        return [str(r) for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []


def _attempt_zone_transfer(domain, ns_list, console):
    results = []
    console.print("  [*] Attempting zone transfer (AXFR) against each NS...")

    for ns in ns_list:
        ns_clean = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_clean)
            zone  = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=6))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name} {rdataset.rdtype} {rdata}")
            results.append({"ns": ns_clean, "ns_ip": ns_ip, "vulnerable": True, "records": records})
            console.print(f"  [bold red]⚠ ZONE TRANSFER SUCCEEDED on {ns_clean} ({ns_ip}) — CRITICAL![/bold red]")
        except Exception:
            results.append({"ns": ns_clean, "vulnerable": False})
            console.print(f"  [green]✓ {ns_clean} — zone transfer refused (secure)[/green]")

    return results


def _analyze_spf(txt_records):
    spf = next((r for r in txt_records if r.startswith('"v=spf1') or r.startswith('v=spf1')), None)
    if not spf:
        return {"found": False, "value": None, "all_mechanism": None,
                "risk": "No SPF record — domain spoofable"}

    spf_clean = spf.strip('"')
    risk, all_mech = "OK", None

    if "+all" in spf_clean:
        all_mech, risk = "+all", "CRITICAL — +all allows ANY server to send as this domain"
    elif "~all" in spf_clean:
        all_mech, risk = "~all", "WEAK — ~all (softfail) does not reject spoofed mail"
    elif "-all" in spf_clean:
        all_mech, risk = "-all", "STRONG — -all (hardfail) rejects unauthorized senders"
    elif "?all" in spf_clean:
        all_mech, risk = "?all", "WEAK — ?all (neutral) provides no protection"

    return {"found": True, "value": spf_clean, "all_mechanism": all_mech, "risk": risk}


def _analyze_dmarc(resolver, domain):
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)
        for r in answers:
            val = str(r).strip('"')
            if "v=DMARC1" in val:
                policy = "none"
                if "p=reject" in val:
                    policy = "reject"
                elif "p=quarantine" in val:
                    policy = "quarantine"
                elif "p=none" in val:
                    policy = "none (monitor only)"
                return {"found": True, "value": val, "policy": policy}
    except Exception:
        pass
    return {"found": False, "value": None, "policy": None,
            "risk": "No DMARC record — phishing emails may reach inboxes"}


def run_dns(target, console):
    console.print(f"[*] Enumerating DNS records for [bold]{target}[/bold]...\n")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 6
    resolver.lifetime = 8

    data = {
        "domain": target,
        "records": {},
        "zone_transfer": [],
        "spf_analysis": {},
        "dmarc_analysis": {},
        "errors": []
    }

    # ── Record enumeration ─────────────────────────────────────────────────
    intel_notes = {
        "A":     "Host → IP mapping; primary attack surface",
        "AAAA":  "IPv6 address; verify it's separately secured",
        "MX":    "Mail server; target for phishing/spoofing analysis",
        "NS":    "Authoritative name servers; target for zone transfer",
        "TXT":   "SPF / DKIM / verification tokens; rich intel source",
        "CNAME": "Alias chain; may reveal cloud/CDN infrastructure",
        "SOA":   "Zone admin email; OSINT pivot point",
    }

    table = Table(title=f"DNS Records — {target}", box=box.SIMPLE_HEAVY,
                  show_header=True, header_style="bold cyan")
    table.add_column("Type",       style="bold yellow", width=8)
    table.add_column("Value",      style="green")
    table.add_column("Intel Note", style="dim")

    for rtype in RECORD_TYPES:
        answers = _resolve(target, rtype, resolver)
        data["records"][rtype] = answers
        if answers:
            first = True
            for answer in answers:
                table.add_row(rtype if first else "", answer, intel_notes.get(rtype, "") if first else "")
                first = False
        else:
            table.add_row(rtype, "[dim]No record[/dim]", intel_notes.get(rtype, ""))

    console.print(table)
    console.print()

    # ── Zone Transfer ──────────────────────────────────────────────────────
    ns_list = data["records"].get("NS", [])
    if ns_list:
        data["zone_transfer"] = _attempt_zone_transfer(target, ns_list, console)
    else:
        console.print("  [yellow][!] No NS records found — skipping zone transfer attempt[/yellow]")

    console.print()

    # ── SPF / DMARC ────────────────────────────────────────────────────────
    spf   = _analyze_spf(data["records"].get("TXT", []))
    dmarc = _analyze_dmarc(resolver, target)
    data["spf_analysis"]   = spf
    data["dmarc_analysis"] = dmarc

    email_lines = []

    if spf["found"]:
        color = "red" if "CRITICAL" in spf["risk"] else ("yellow" if "WEAK" in spf["risk"] else "green")
        email_lines.append(f"[bold white]SPF:[/bold white]   [{color}]{spf['risk']}[/{color}]")
        email_lines.append(f"       [dim]{spf['value'][:80]}[/dim]")
    else:
        email_lines.append("[bold white]SPF:[/bold white]   [bold red]NOT FOUND — domain can be spoofed in email From: header[/bold red]")

    email_lines.append("")

    if dmarc["found"]:
        pc = "green" if dmarc["policy"] == "reject" else ("yellow" if dmarc["policy"] == "quarantine" else "red")
        email_lines.append(f"[bold white]DMARC:[/bold white] Policy = [{pc}]{dmarc['policy']}[/{pc}]")
        email_lines.append(f"       [dim]{dmarc['value'][:80]}[/dim]")
    else:
        email_lines.append(f"[bold white]DMARC:[/bold white] [bold red]NOT FOUND — {dmarc.get('risk', '')}[/bold red]")

    email_lines.append("")
    spf_weak   = not spf["found"] or "WEAK" in spf.get("risk","") or "CRITICAL" in spf.get("risk","")
    dmarc_weak = not dmarc["found"] or dmarc.get("policy") == "none"

    if spf_weak and dmarc_weak:
        email_lines.append("[bold red]⚠ VERDICT: HIGH phishing risk — emails can be spoofed from this domain[/bold red]")
    elif spf_weak or dmarc_weak:
        email_lines.append("[yellow]→ VERDICT: MEDIUM phishing risk — partial email security[/yellow]")
    else:
        email_lines.append("[green]✓ VERDICT: LOW phishing risk — SPF + DMARC enforced[/green]")

    console.print(Panel(
        "\n".join(email_lines),
        title="[bold cyan]EMAIL SECURITY ANALYSIS (SPF / DMARC)[/bold cyan]",
        border_style="cyan", box=box.ROUNDED
    ))
    console.print()

    # ── SOA admin email ────────────────────────────────────────────────────
    soa_records = data["records"].get("SOA", [])
    if soa_records:
        parts = soa_records[0].split()
        if len(parts) >= 2:
            admin_email = parts[1].replace(".", "@", 1).rstrip(".")
            console.print(
                f"[bold white]SOA Admin Contact:[/bold white] [cyan]{admin_email}[/cyan]  "
                "[dim]← pivot: LinkedIn, HaveIBeenPwned, email harvesting[/dim]"
            )
            console.print()

    return data
