"""
Module: subdomain_enum.py
Purpose: Passive subdomain discovery via Certificate Transparency logs

Techniques:
  - Certificate Transparency log mining via crt.sh
  - Fully passive — no direct contact with target infrastructure
  - Live host validation via DNS A record resolution
  - Pattern-based classification for high-interest subdomains

Why CT logs?
  Every SSL/TLS certificate issued by a public CA is logged to
  Certificate Transparency logs by design. crt.sh indexes these
  publicly. This lets us enumerate subdomains without sending a
  single packet to the target — purely passive reconnaissance.
"""

import requests
import dns.resolver
from rich.table import Table
from rich import box
from rich.panel import Panel


INTERESTING_PATTERNS = [
    "admin", "administrator", "portal", "dashboard", "manage", "management",
    "dev", "develop", "development", "staging", "stage", "uat", "test", "qa",
    "api", "api2", "v1", "v2", "graphql", "rest",
    "vpn", "remote", "access", "citrix",
    "mail", "webmail", "smtp", "pop", "imap",
    "ftp", "sftp", "ssh",
    "jenkins", "ci", "cd", "gitlab", "github", "jira", "confluence",
    "elastic", "kibana", "grafana", "prometheus",
    "backup", "old", "legacy", "archive",
    "internal", "intranet", "corp",
    "cdn", "static", "assets", "media",
    "login", "auth", "sso", "oauth",
    "db", "database", "mysql", "mongo", "redis",
    "aws", "s3", "azure", "gcp",
    "beta", "alpha", "preview",
]


def _query_crtsh(domain):
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=50,
            headers={"Accept": "application/json"}
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


def _extract_subdomains(crt_data, base_domain):
    found = set()
    for entry in crt_data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(f".{base_domain}") or name == base_domain:
                found.add(name)
    return sorted(found)


def _resolve_host(hostname):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 4
        resolver.lifetime = 5
        return [str(r) for r in resolver.resolve(hostname, "A")]
    except Exception:
        return []


def _classify_subdomain(subdomain, base_domain):
    prefix = subdomain.replace(f".{base_domain}", "").lower()
    for pattern in INTERESTING_PATTERNS:
        if pattern in prefix:
            return pattern
    return None


def run_subdomain_enum(target, console):
    console.print(f"[*] Querying Certificate Transparency logs (crt.sh) for [bold]{target}[/bold]...")
    console.print("  [dim]Fully passive — no packets sent to target[/dim]\n")

    data = {
        "domain": target,
        "total_ct_entries": 0,
        "unique_subdomains": [],
        "live_subdomains": [],
        "interesting_subdomains": [],
        "errors": []
    }

    crt_data = _query_crtsh(target)
    if not crt_data:
        console.print("  [yellow][!] No CT log data returned. crt.sh may have timed out.[/yellow]")
        data["errors"].append("crt.sh returned no data")
        return data

    data["total_ct_entries"] = len(crt_data)
    console.print(f"  [green]✓ {len(crt_data)} certificate log entries found[/green]")

    subdomains = _extract_subdomains(crt_data, target)
    data["unique_subdomains"] = subdomains
    console.print(f"  [green]✓ {len(subdomains)} unique subdomains extracted[/green]\n")

    if not subdomains:
        console.print("  [yellow]No subdomains found in CT logs.[/yellow]")
        return data

    console.print("[*] Validating live hosts via DNS resolution...\n")

    live, interesting = [], []

    table = Table(title=f"Subdomains — {target}", box=box.SIMPLE_HEAVY,
                  show_header=True, header_style="bold cyan")
    table.add_column("Subdomain", style="white",      min_width=35)
    table.add_column("IP(s)",     style="green",      min_width=18)
    table.add_column("Status",    width=10)
    table.add_column("Flag",      style="yellow")

    for subdomain in subdomains:
        ips     = _resolve_host(subdomain)
        is_live = bool(ips)
        pattern = _classify_subdomain(subdomain, target)

        if is_live:
            live.append({"subdomain": subdomain, "ips": ips, "pattern": pattern})
        if pattern and is_live:
            interesting.append({"subdomain": subdomain, "ips": ips, "pattern": pattern})

        status_str   = "[bold green]LIVE[/bold green]" if is_live else "[dim]dead[/dim]"
        ip_str       = ", ".join(ips) if ips else "[dim]unresolved[/dim]"
        interest_str = (f"[bold red]⚠ {pattern}[/bold red]" if pattern and is_live
                        else f"[dim yellow]{pattern}[/dim yellow]" if pattern else "")

        table.add_row(subdomain, ip_str, status_str, interest_str)

    data["live_subdomains"]        = live
    data["interesting_subdomains"] = interesting

    console.print(table)
    console.print()

    console.print(Panel(
        f"[white]CT log entries :[/white]   [cyan]{data['total_ct_entries']}[/cyan]\n"
        f"[white]Unique subdomains:[/white]  [cyan]{len(subdomains)}[/cyan]\n"
        f"[white]Live hosts       :[/white]  [bold green]{len(live)}[/bold green]\n"
        f"[white]High-interest    :[/white]  [bold red]{len(interesting)}[/bold red]",
        title="[bold cyan]SUBDOMAIN SUMMARY[/bold cyan]",
        border_style="cyan", box=box.ROUNDED
    ))

    if interesting:
        console.print()
        console.print("[bold yellow]⚠ HIGH-INTEREST SUBDOMAINS:[/bold yellow]")
        for item in interesting:
            console.print(
                f"  [bold red]→[/bold red] [bold white]{item['subdomain']}[/bold white]  "
                f"[green]{', '.join(item['ips'])}[/green]  "
                f"[dim yellow]({item['pattern']})[/dim yellow]"
            )
        console.print(
            "\n  [dim]These patterns often indicate: reduced security controls, test\n"
            "  credentials, unpatched services, or internal tooling exposed to internet.[/dim]"
        )

    console.print()
    return data
