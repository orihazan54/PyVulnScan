"""
PyVulnScan - Network Vulnerability Scanner
==========================================
Main entry point. Coordinates the scanning process:
1. Port scanning to find open ports
2. Service detection to identify what's running on each port
3. CVE lookup to find known vulnerabilities for each service
"""

import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.port_scanner import scan_ports, COMMON_PORTS
from scanner.service_detector import detect_service
from scanner.cve_checker import check_services_for_cves


console = Console()


def print_banner():
    """Prints a nice ASCII banner when the tool starts."""
    banner = """
    ╔═══════════════════════════════════════╗
    ║       PyVulnScan v0.2                 ║
    ║   Network Vulnerability Scanner       ║
    ╚═══════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def parse_arguments() -> argparse.Namespace:
    """Sets up command-line argument parsing."""
    parser = argparse.ArgumentParser(
        description="A network vulnerability scanner that identifies open ports, services, and CVEs.",
        epilog="Example: python main.py --target scanme.nmap.org"
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target hostname or IP address to scan"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per port in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip CVE lookup (faster, but less detailed)"
    )
    
    return parser.parse_args()


def display_services_table(target: str, services: list) -> None:
    """Displays detected services in a formatted table."""
    table = Table(
        title=f"Open Ports & Services - {target}",
        title_style="bold magenta",
        show_lines=True
    )
    
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Service", style="green")
    table.add_column("Product", style="yellow")
    table.add_column("Version", style="red")
    table.add_column("Banner", style="dim", overflow="fold", max_width=40)
    
    for svc in services:
        table.add_row(
            str(svc.port),
            svc.service,
            svc.product or "—",
            svc.version or "—",
            svc.banner or "—"
        )
    
    console.print()
    console.print(table)


def display_cves_table(cve_results: list) -> None:
    """Displays found CVEs in a formatted table."""
    if not cve_results:
        console.print("\n[yellow]No CVE data available (no services with version info).[/yellow]")
        return
    
    # Color mapping for severity levels
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "dim"
    }
    
    total_cves = sum(len(r.cves) for r in cve_results)
    
    if total_cves == 0:
        console.print("\n[green]No known CVEs found for detected services.[/green]")
        return
    
    table = Table(
        title=f"Vulnerabilities Found ({total_cves} CVEs)",
        title_style="bold red",
        show_lines=True
    )
    
    table.add_column("Product", style="yellow")
    table.add_column("Version", style="cyan")
    table.add_column("CVE ID", style="white")
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("Description", overflow="fold", max_width=60)
    
    for result in cve_results:
        if result.error:
            console.print(f"[red]Error checking {result.product}: {result.error}[/red]")
            continue
        
        # Show top 5 CVEs per product to keep output readable
        for cve in result.cves[:5]:
            severity_style = severity_colors.get(cve.severity, "white")
            table.add_row(
                result.product,
                result.version,
                cve.id,
                f"[{severity_style}]{cve.severity}[/{severity_style}]",
                f"{cve.score:.1f}",
                cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
            )
    
    console.print()
    console.print(table)


def display_summary(services: list, cve_results: list) -> None:
    """Prints a summary of the scan."""
    total_cves = sum(len(r.cves) for r in cve_results) if cve_results else 0
    critical = sum(
        1 for r in cve_results for cve in r.cves
        if cve.severity == "CRITICAL"
    ) if cve_results else 0
    high = sum(
        1 for r in cve_results for cve in r.cves
        if cve.severity == "HIGH"
    ) if cve_results else 0
    
    summary = (
        f"[bold]Scan Summary[/bold]\n\n"
        f"  Open ports:        [cyan]{len(services)}[/cyan]\n"
        f"  Services detected: [green]{sum(1 for s in services if s.product)}[/green]\n"
        f"  Total CVEs:        [yellow]{total_cves}[/yellow]\n"
        f"  Critical CVEs:     [bold red]{critical}[/bold red]\n"
        f"  High CVEs:         [red]{high}[/red]"
    )
    
    console.print()
    console.print(Panel(summary, border_style="cyan"))


def main():
    """Main entry point - orchestrates the entire scan."""
    print_banner()
    args = parse_arguments()
    target = args.target
    
    # ═══════════════════════════════════════════════
    # Phase 1: Port Scanning
    # ═══════════════════════════════════════════════
    console.print(f"\n[bold]Phase 1:[/bold] Port scanning [cyan]{target}[/cyan]...")
    
    try:
        open_ports = scan_ports(
            target=target,
            ports=COMMON_PORTS,
            timeout=args.timeout,
            max_workers=args.threads
        )
    except KeyboardInterrupt:
        console.print("\n[red]Scan interrupted by user[/red]")
        sys.exit(1)
    
    if not open_ports:
        console.print("[yellow]No open ports found. Exiting.[/yellow]")
        return
    
    # ═══════════════════════════════════════════════
    # Phase 2: Service Detection
    # ═══════════════════════════════════════════════
    console.print(f"\n[bold]Phase 2:[/bold] Detecting services on {len(open_ports)} open ports...")
    
    services = []
    for port in open_ports:
        console.print(f"  [dim]Probing port {port}...[/dim]")
        info = detect_service(target, port, timeout=args.timeout * 3)
        services.append(info)
    
    display_services_table(target, services)
    
    # ═══════════════════════════════════════════════
    # Phase 3: CVE Lookup (optional)
    # ═══════════════════════════════════════════════
    cve_results = []
    
    if args.no_cve:
        console.print("\n[yellow]Skipping CVE lookup (--no-cve flag used)[/yellow]")
    else:
        services_with_version = [s for s in services if s.product and s.version]
        
        if not services_with_version:
            console.print("\n[yellow]No services with detected versions - skipping CVE lookup.[/yellow]")
        else:
            console.print(
                f"\n[bold]Phase 3:[/bold] Checking CVEs for "
                f"{len(services_with_version)} services..."
            )
            console.print("[dim](This may take a while due to NVD API rate limits)[/dim]\n")
            
            try:
                cve_results = check_services_for_cves(services)
                display_cves_table(cve_results)
            except KeyboardInterrupt:
                console.print("\n[red]CVE lookup interrupted[/red]")
    
    # ═══════════════════════════════════════════════
    # Final Summary
    # ═══════════════════════════════════════════════
    display_summary(services, cve_results)
    
    # Generate HTML report
    console.print("\n[bold]Generating HTML report...[/bold]")
    from reporter.html_reporter import generate_html_report
    
    report_path = generate_html_report(
        target=target,
        services=services,
        cve_results=cve_results,
        output_path=f"report_{target.replace('.', '_')}.html"
    )
    
    console.print(f"[green]✓ Report saved to:[/green] [cyan]{report_path}[/cyan]")
    console.print(f"\n[bold green]✓ Scan complete![/bold green]\n")


if __name__ == "__main__":
    main()