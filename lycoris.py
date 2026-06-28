#!/usr/bin/env python3

import click
import json
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text
from rich.style import Style

from modules.whois_recon import run_whois
from modules.dns_recon import run_dns
from modules.subdomain_enum import run_subdomain_enum
from modules.report_gen import generate_report, generate_html_report

console = Console()

# Lycoris Recoil uniform palette
# Crimson red  → #C8102E  (the blazer)
# Navy blue    → #1B1F5E  (the ribbon / trim)
# We alternate lines across the banner to blend both

BANNER_LINES = [
    "██╗      ██╗   ██╗ ██████╗ ██████╗ ██████╗ ██╗███████╗",
    "██║      ╚██╗ ██╔╝██╔════╝██╔═══██╗██╔══██╗██║██╔════╝",
    "██║       ╚████╔╝ ██║     ██║   ██║██████╔╝██║███████╗",
    "██║        ╚██╔╝  ██║     ██║   ██║██╔══██╗██║╚════██║",
    "███████╗    ██║   ╚██████╗╚██████╔╝██║  ██║██║███████║",
    "╚══════╝    ╚═╝    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝",
]

CRIMSON = Style(color="#C8102E", bold=True)
NAVY    = Style(color="#4A55A2", bold=True)   # lighter navy so it's visible on dark terminals
MID     = Style(color="#9B2048", bold=True)   # crimson-navy blend for middle lines

LINE_STYLES = [CRIMSON, CRIMSON, MID, MID, NAVY, NAVY]


def print_banner():
    console.print()
    for line, style in zip(BANNER_LINES, LINE_STYLES):
        t = Text(line, style=style)
        console.print(t, justify="left")
    console.print()


META = (
    "  [bold white]Lycoris[/bold white] [dim]v1.0[/dim]  ·  "
    "[dim]Modular OSINT & Footprinting Framework[/dim]\n"
    "  [dim]Author: Aswin  |  https://github.com/18Aswin/lycoris[/dim]"
)

DISCLAIMER = (
    "[yellow]⚠  Authorized use only. Use against targets you own or have explicit written\n"
    "   permission to test. Unauthorized recon may violate applicable computer laws.[/yellow]"
)


def print_help_screen():
    print_banner()
    console.print(META)
    console.print()
    console.print(Panel(DISCLAIMER, border_style="#C8102E", box=box.ROUNDED))
    console.print()

    console.print("  [bold white]Usage:[/bold white]")
    console.print(
        "    [bold green]python lycoris.py[/bold green] "
        "[cyan]-t[/cyan] [white]<target>[/white] "
        "[dim][[cyan]-m[/cyan] [white]<modules>[/white]] "
        "[[cyan]-o[/cyan] [white]<dir>[/white]] "
        "[[cyan]-r[/cyan]] "
        "[[cyan]--html[/cyan]][/dim]"
    )
    console.print()

    opt_table = Table(box=box.SIMPLE, show_header=True, header_style="bold #C8102E", padding=(0, 2))
    opt_table.add_column("Flag",        style="#4A55A2 bold", width=20)
    opt_table.add_column("Description", style="white",        width=46)
    opt_table.add_column("Default",     style="dim yellow",   width=14)

    opt_table.add_row("-t, --target",  "Target domain to footprint",                  "required")
    opt_table.add_row("-m, --modules", "Modules to run (see below)",                  "all")
    opt_table.add_row("-o, --output",  "Output directory for JSON + report",          "output/")
    opt_table.add_row("-r, --report",  "Generate Markdown intelligence report",       "off")
    opt_table.add_row("--html",        "Generate HTML intelligence report",           "off")
    opt_table.add_row("--shodan-key",  "Shodan API key (or env SHODAN_API_KEY)",      "none")
    opt_table.add_row("-h, --help",    "Show this help screen",                       "")

    console.print("  [bold white]Options:[/bold white]")
    console.print(opt_table)

    mod_table = Table(box=box.SIMPLE, show_header=True, header_style="bold #C8102E", padding=(0, 2))
    mod_table.add_column("Module",       style="bold #9B2048", width=16)
    mod_table.add_column("What it does", style="white",        width=52)

    mod_table.add_row("whois",                  "WHOIS/RDAP lookup, registrar, domain age, privacy detection")
    mod_table.add_row("dns",                    "A/MX/NS/TXT/SOA records, zone transfer, SPF/DMARC analysis")
    mod_table.add_row("subdomains",             "CT log mining via crt.sh, live resolution, pattern flagging")
    mod_table.add_row("[dim]shodan[/dim]",       "[dim]IP intel, open ports, banners (coming v1.1)[/dim]")
    mod_table.add_row("[dim]emails[/dim]",       "[dim]Email harvesting via Hunter.io (coming v1.2)[/dim]")
    mod_table.add_row("[dim]dorks[/dim]",        "[dim]Automated Google dorking (coming v1.3)[/dim]")
    mod_table.add_row("all",                    "Run all available modules")

    console.print("  [bold white]Modules:[/bold white]")
    console.print(mod_table)

    console.print("  [bold white]Examples:[/bold white]\n")
    examples = [
        ("Full scan with Markdown report",         "python lycoris.py -t example.com -m all -r"),
        ("Full scan with HTML report",             "python lycoris.py -t example.com -m all --html"),
        ("WHOIS + DNS only",                       "python lycoris.py -t example.com -m whois,dns"),
        ("Subdomains, custom output dir",          "python lycoris.py -t example.com -m subdomains -o ~/recon"),
        ("With Shodan key from env",               "SHODAN_API_KEY=xyz python lycoris.py -t example.com -r"),
    ]
    for label, cmd in examples:
        console.print(f"    [dim]# {label}[/dim]")
        console.print(f"    [bold green]$ {cmd}[/bold green]\n")

    console.print(
        "  [dim]Output: JSON session    →  output/<target>_<timestamp>.json[/dim]\n"
        "  [dim]         Markdown report →  output/<target>_<timestamp>_report.md[/dim]\n"
        "  [dim]         HTML report     →  output/<target>_<timestamp>_report.html[/dim]"
    )
    console.print()


def print_banner_compact():
    print_banner()
    console.print(META)
    console.print()
    console.print(Panel(DISCLAIMER, border_style="#C8102E", box=box.ROUNDED))
    console.print()


def save_session(target, results, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/{target}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2, default=str)
    return filename


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--target",    "-t", default=None,     help="Target domain (e.g. example.com)")
@click.option("--modules",   "-m", default="all",    help="Comma-separated: whois,dns,subdomains,all")
@click.option("--output",    "-o", default="output", help="Output directory (default: output)")
@click.option("--report",    "-r", is_flag=True,     help="Generate Markdown intelligence report")
@click.option("--html",            is_flag=True,     help="Generate HTML intelligence report (in addition to JSON)")
@click.option("--shodan-key",      envvar="SHODAN_API_KEY", default=None, help="Shodan API key")
def main(target, modules, output, report, html, shodan_key):
    """Lycoris — Modular OSINT & Footprinting Framework"""

    if not target:
        print_help_screen()
        sys.exit(0)

    print_banner_compact()

    target = target.lower().strip().replace("https://", "").replace("http://", "").rstrip("/")

    console.print(Panel(
        f"[bold white]Target  :[/bold white]  [bold #C8102E]{target}[/bold #C8102E]\n"
        f"[bold white]Modules :[/bold white]  [#4A55A2]{modules}[/#4A55A2]\n"
        f"[bold white]Output  :[/bold white]  [dim]{output}/[/dim]\n"
        f"[bold white]Markdown Report  :[/bold white]  {'[bold #9B2048]yes[/bold #9B2048]' if report else '[dim]no[/dim]'}\n"
        f"[bold white]HTML Report      :[/bold white]  {'[bold #9B2048]yes[/bold #9B2048]' if html else '[dim]no[/dim]'}\n"
        f"[bold white]Started :[/bold white]  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold #C8102E]ENGAGEMENT PARAMETERS[/bold #C8102E]",
        border_style="#9B2048",
        box=box.ROUNDED
    ))
    console.print()

    selected = [m.strip() for m in modules.split(",")] if modules != "all" else ["whois", "dns", "subdomains"]

    results = {
        "meta": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "modules_run": selected,
            "tool": "Lycoris v1.0"
        }
    }

    # ── Progress bar ──────────────────────────────────────────────────────
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn, SpinnerColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:

        overall_task = progress.add_task(
            "[cyan]Running modules...[/cyan]",
            total=len(selected)
        )

        for mod in selected:
            if mod == "whois":
                progress.update(overall_task, description="[bold #C8102E]WHOIS Intelligence[/bold #C8102E]")
                console.print()
                results["whois"] = run_whois(target, console)
            elif mod == "dns":
                progress.update(overall_task, description="[bold #4A55A2]DNS Enumeration[/bold #4A55A2]")
                console.print()
                results["dns"] = run_dns(target, console)
            elif mod == "subdomains":
                progress.update(overall_task, description="[bold #9B2048]Subdomain Enumeration[/bold #9B2048]")
                console.print()
                results["subdomains"] = run_subdomain_enum(target, console)
            progress.advance(overall_task)

    # ── Save session ──────────────────────────────────────────────────────
    session_file = save_session(target, results, output)

    console.print()
    console.rule("[bold #C8102E]SCAN COMPLETE[/bold #C8102E]")
    console.print(f"\n[bold white]Session JSON :[/bold white]  [#9B2048]{session_file}[/#9B2048]")

    if report:
        report_file = generate_report(target, results, output, console)
        console.print(f"[bold white]Markdown Report :[/bold white]  [#9B2048]{report_file}[/#9B2048]")

    if html:
        html_file = generate_html_report(target, results, output, console)
        console.print(f"[bold white]HTML Report     :[/bold white]  [#9B2048]{html_file}[/#9B2048]")

    console.print()


if __name__ == "__main__":
    main()
