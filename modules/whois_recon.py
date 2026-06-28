"""
Module: whois_recon.py
Purpose: WHOIS lookup and domain intelligence gathering

Techniques:
  - WHOIS lookup via python-whois
  - RDAP fallback for privacy-protected or sparse WHOIS responses
  - Domain age calculation
  - Registrar and registrant analysis
  - Privacy protection detection
  - DNSSEC status check
"""

import whois
import requests
from datetime import datetime, timezone
from rich.table import Table
from rich import box
from rich.panel import Panel


def _safe_str(val):
    if val is None:
        return "N/A"
    if isinstance(val, list):
        val = val[0] if val else "N/A"
    return str(val).strip()


def _calc_age(creation_date):
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
        return (now - creation_date).days
    return None


def _rdap_fallback(domain):
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def run_whois(target, console):
    console.print(f"[*] Querying WHOIS for [bold]{target}[/bold]...")

    data = {
        "domain": target,
        "registrar": "N/A",
        "registrar_url": "N/A",
        "registrant_org": "N/A",
        "registrant_country": "N/A",
        "registrant_email": "N/A",
        "created": "N/A",
        "expires": "N/A",
        "updated": "N/A",
        "domain_age_days": None,
        "name_servers": [],
        "status": [],
        "dnssec": "N/A",
        "privacy_protected": False,
        "rdap_used": False,
        "errors": []
    }

    try:
        w = whois.whois(target)
        data["registrar"]          = _safe_str(w.registrar)
        data["registrar_url"]      = _safe_str(w.get("referral_url") or w.get("registrar_url"))
        data["registrant_org"]     = _safe_str(w.org)
        data["registrant_country"] = _safe_str(w.country)
        data["registrant_email"]   = _safe_str(w.emails)
        data["created"]            = _safe_str(w.creation_date)
        data["expires"]            = _safe_str(w.expiration_date)
        data["updated"]            = _safe_str(w.updated_date)
        data["domain_age_days"]    = _calc_age(w.creation_date)
        data["dnssec"]             = _safe_str(w.get("dnssec"))

        ns = w.name_servers
        if ns:
            data["name_servers"] = sorted(set(
                s.lower().rstrip(".") for s in ns if isinstance(s, str)
            ))

        status = w.status
        if status:
            if isinstance(status, str):
                status = [status]
            data["status"] = [s.split(" ")[0] for s in status]

        privacy_keywords = ["privacy", "redacted", "whoisguard", "domains by proxy",
                            "contact privacy", "withheld", "protect"]
        combined = " ".join([
            data["registrant_org"], data["registrant_email"], data["registrant_country"]
        ]).lower()
        data["privacy_protected"] = any(kw in combined for kw in privacy_keywords)

    except Exception as e:
        data["errors"].append(f"python-whois error: {str(e)}")
        console.print("  [yellow][!] WHOIS partial/failed. Trying RDAP...[/yellow]")

        rdap = _rdap_fallback(target)
        if rdap:
            data["rdap_used"] = True
            events = rdap.get("events", [])
            for ev in events:
                action = ev.get("eventAction", "")
                date   = ev.get("eventDate", "N/A")
                if action == "registration":
                    data["created"] = date
                elif action == "expiration":
                    data["expires"] = date
                elif action == "last changed":
                    data["updated"] = date
            ns_list = [n.get("ldhName", "") for n in rdap.get("nameservers", [])]
            data["name_servers"] = [n.lower().rstrip(".") for n in ns_list if n]
        else:
            data["errors"].append("RDAP fallback also failed.")

    # ── Render ─────────────────────────────────────────────────────────────
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Field",  style="bold white", width=24)
    table.add_column("Value",  style="green")

    rows = [
        ("Domain",             data["domain"]),
        ("Registrar",          data["registrar"]),
        ("Registrar URL",      data["registrar_url"]),
        ("Registrant Org",     data["registrant_org"]),
        ("Registrant Country", data["registrant_country"]),
        ("Registrant Email",   data["registrant_email"]),
        ("Created",            data["created"]),
        ("Expires",            data["expires"]),
        ("Updated",            data["updated"]),
        ("Domain Age",         f"{data['domain_age_days']} days" if data["domain_age_days"] else "N/A"),
        ("DNSSEC",             data["dnssec"]),
        ("Privacy Protected",  "[bold red]YES[/bold red]" if data["privacy_protected"] else "[green]NO[/green]"),
        ("Source",             "RDAP" if data["rdap_used"] else "WHOIS"),
    ]
    for field, value in rows:
        table.add_row(field, value)
    console.print(table)

    if data["name_servers"]:
        console.print("\n[bold white]Name Servers:[/bold white]")
        for ns in data["name_servers"]:
            console.print(f"  [cyan]→[/cyan] {ns}")

    if data["status"]:
        status_info = {
            "clientTransferProhibited": "Transfer locked by registrar",
            "clientDeleteProhibited":   "Delete locked by registrar",
            "clientUpdateProhibited":   "Update locked by registrar",
            "serverHold":               "[red]⚠ Domain suspended[/red]",
            "ok":                       "Active, no restrictions",
        }
        console.print("\n[bold white]Domain Status:[/bold white]")
        for s in data["status"]:
            meaning = status_info.get(s, "")
            console.print(f"  [cyan]→[/cyan] {s}  [dim]{meaning}[/dim]")

    notes = []
    if data["domain_age_days"] and data["domain_age_days"] < 180:
        notes.append("[bold red]⚠ Domain is less than 6 months old[/bold red]")
    if data["privacy_protected"]:
        notes.append("[yellow]⚠ WHOIS privacy enabled — registrant identity hidden[/yellow]")
    if data["dnssec"] and data["dnssec"].lower() in ["unsigned", "n/a", "no"]:
        notes.append("[yellow]→ DNSSEC not enabled — domain vulnerable to DNS spoofing[/yellow]")

    if notes:
        console.print()
        console.print(Panel(
            "\n".join(notes),
            title="[bold yellow]INTELLIGENCE NOTES[/bold yellow]",
            border_style="yellow", box=box.ROUNDED
        ))

    for err in data["errors"]:
        console.print(f"  [red][!] {err}[/red]")

    console.print()
    return data
