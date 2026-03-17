#!/usr/bin/env python3
"""
VulnScan — Async Python Vulnerability Scanner
Usage:
    python main.py <target> [<target2> ...] [options]

Examples:
    python main.py 192.168.1.1
    python main.py example.com --ports 22 80 443 8080
    python main.py 10.0.0.1 10.0.0.2 --output reports/scan --json
    python main.py 192.168.1.0/24 --timeout 1.5
"""
import asyncio
import argparse
import ipaddress
import os
import sys
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from scanner import ScanTarget, ScanResult, run_scan, run_detections
from reports import generate_html_report, generate_json_report

console = Console() if HAS_RICH else None

BANNER = r"""
 __   __      _      _____
 \ \ / /     | |    / ____|
  \ V / _   _| |   | (___   ___ __ _ _ __
   > < | | | | |    \___ \ / __/ _` | '_ \\
  / . \| |_| | |____) __) | (_| (_| | | | |
 /_/ \_\\__,_|______|____/ \___\__,_|_| |_|

  Async Vulnerability Scanner  |  Python 3.9+
  By - RAVI CHAUHAN  |  github.com/Ravirazchauhan
"""

SEVERITY_COLORS = {
    "critical": "bright_red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "info":     "dim",
}


def expand_cidr(cidr: str):
    """Expand a CIDR block into individual host IPs."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [cidr]


def print_banner():
    if HAS_RICH:
        console.print(BANNER, style="bold cyan")
    else:
        print(BANNER)


def print_result(result: ScanResult):
    if not HAS_RICH:
        print(f"\n[{result.target}] {len(result.open_ports)} open ports, {len(result.vulnerabilities)} vulns, risk={result.risk_score}")
        return

    # ── Port table ───────────────────────────────────────────────────────────
    port_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    port_table.add_column("Port", style="cyan", width=8)
    port_table.add_column("Service", style="blue", width=14)
    port_table.add_column("Latency", width=10)
    port_table.add_column("Banner", style="dim")

    for p in sorted(result.open_ports, key=lambda x: x.port):
        port_table.add_row(
            str(p.port),
            p.service,
            f"{p.latency_ms:.1f}ms",
            (p.banner or "")[:80],
        )

    # ── Vuln table ───────────────────────────────────────────────────────────
    vuln_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
    vuln_table.add_column("Severity", width=10)
    vuln_table.add_column("ID", width=14)
    vuln_table.add_column("Finding")
    vuln_table.add_column("Port", width=7)

    for v in sorted(result.vulnerabilities, key=lambda x: ["critical","high","medium","low","info"].index(x.get("severity","info"))):
        sev = v.get("severity", "info")
        vuln_table.add_row(
            Text(sev.upper(), style=f"bold {SEVERITY_COLORS.get(sev,'dim')}"),
            v["id"],
            v["title"],
            str(v.get("port", "—")),
        )

    risk_color = "bright_red" if result.risk_score >= 70 else "red" if result.risk_score >= 40 else "yellow" if result.risk_score >= 15 else "green"

    console.print(Panel(
        f"[bold]{result.target}[/bold]  [dim]→[/dim]  {result.ip}   "
        f"[dim]·[/dim]  {result.duration_seconds:.1f}s   "
        f"[dim]·[/dim]  Risk: [{risk_color}]{result.risk_score}/100[/{risk_color}]",
        title="[bold]Scan Result[/bold]",
        border_style="cyan",
    ))

    if result.open_ports:
        console.print(f"  [bold cyan]Open Ports ({len(result.open_ports)})[/bold cyan]")
        console.print(port_table)

    if result.vulnerabilities:
        console.print(f"  [bold magenta]Vulnerabilities ({len(result.vulnerabilities)})[/bold magenta]")
        console.print(vuln_table)
    else:
        console.print("  [green]✓ No vulnerabilities detected[/green]\n")


async def scan_target(target_str: str, ports: list, timeout: float, progress=None, task_id=None) -> ScanResult:
    target = ScanTarget(host=target_str, ports=ports, timeout=timeout)
    result = await run_scan(target)
    result = run_detections(result)
    if progress and task_id is not None:
        progress.advance(task_id)
    return result


async def main_async(args):
    # Expand any CIDR blocks
    all_targets = []
    for t in args.targets:
        if "/" in t:
            expanded = expand_cidr(t)
            all_targets.extend(expanded)
            if HAS_RICH:
                console.print(f"[dim]Expanded {t} → {len(expanded)} hosts[/dim]")
        else:
            all_targets.append(t)

    ports = args.ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

    if HAS_RICH:
        console.print(f"\n[bold]Targets:[/bold] {len(all_targets)}   [bold]Ports:[/bold] {len(ports)}   [bold]Timeout:[/bold] {args.timeout}s\n")
    else:
        print(f"Scanning {len(all_targets)} target(s) on {len(ports)} ports...")

    results = []
    start = time.monotonic()

    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(all_targets))
            tasks = [scan_target(t, ports, args.timeout, progress, task) for t in all_targets]
            results = await asyncio.gather(*tasks)
    else:
        tasks = [scan_target(t, ports, args.timeout) for t in all_targets]
        results = await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start

    for r in results:
        print_result(r)

    # ── Summary ─────────────────────────────────────────────────────────────
    total_vulns = sum(len(r.vulnerabilities) for r in results)
    total_open  = sum(len(r.open_ports) for r in results)

    if HAS_RICH:
        summary = Table(box=box.ROUNDED, title="[bold]Scan Summary[/bold]", title_style="bold white")
        summary.add_column("Metric", style="dim")
        summary.add_column("Value", style="bold")
        summary.add_row("Targets scanned", str(len(results)))
        summary.add_row("Total open ports", str(total_open))
        summary.add_row("Total vulnerabilities", f"[{'red' if total_vulns else 'green'}]{total_vulns}[/{'red' if total_vulns else 'green'}]")
        summary.add_row("Scan duration", f"{elapsed:.1f}s")
        console.print(summary)

    # ── Reports ──────────────────────────────────────────────────────────────
    if args.output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = f"{args.output}_{ts}.html"
        generate_html_report(list(results), html_path)
        if HAS_RICH:
            console.print(f"\n[green]✓ HTML report:[/green] {html_path}")
        else:
            print(f"HTML report: {html_path}")

        if args.json:
            json_path = f"{args.output}_{ts}.json"
            generate_json_report(list(results), json_path)
            if HAS_RICH:
                console.print(f"[green]✓ JSON report:[/green] {json_path}")
            else:
                print(f"JSON report: {json_path}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnScan — Async Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("targets", nargs="+", help="Host(s) or CIDR range(s) to scan")
    parser.add_argument("--ports", nargs="+", type=int, help="Ports to scan (default: common ports)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("--output", "-o", help="Output path prefix for reports (e.g. reports/scan)")
    parser.add_argument("--json", action="store_true", help="Also export JSON report")
    args = parser.parse_args()

    print_banner()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
