"""
PyVulnScan - Network Vulnerability Scanner
==========================================
Main entry point. Coordinates the scanning process:
1. Port scanning to find open ports
2. Service detection to identify what's running on each port
"""

import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from scanner.port_scanner import scan_ports, COMMON_PORTS
from scanner.service_detector import detect_service


# Rich's Console object - replaces print() with colored, formatted output
console = Console()


def print_banner():
    """Prints a nice ASCII banner when the tool starts."""
    banner = """
    ╔═══════════════════════════════════════╗
    ║       PyVulnScan v0.1                 ║
    ║   Network Vulnerability Scanner       ║
    ╚═══════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


def parse_arguments() -> argparse.Namespace:
    """
    Sets up command-line argument parsing.
    
    Returns:
        Namespace object with all the arguments the user provided.
    """
    parser = argparse.ArgumentParser(
        description="A network vulnerability scanner that identifies open ports and services.",
        epilog="Example: python main.py --target scanme.nmap.org"
    )
    
    # Required: the target to scan
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target hostname or IP address to scan"
    )
    
    # Optional: timeout per port
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout per port in seconds (default: 1.0)"
    )
    
    # Optional: number of threads
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    
    return parser.parse_args()


def display_results(target: str, services: list) -> None:
    """
    Displays scan results in a nice formatted table.
    
    Args:
        target: The scanned target
        services: List of ServiceInfo objects from the detector
    """
    if not services:
        console.print("\n[yellow]No open ports found.[/yellow]")
        return
    
    # Create a Rich table - much nicer than plain print()
    table = Table(
        title=f"Scan Results for {target}",
        title_style="bold magenta",
        show_lines=True
    )
    
    # Add columns
    table.add_column("Port", style="cyan", justify="center")
    table.add_column("Service", style="green")
    table.add_column("Product", style="yellow")
    table.add_column("Version", style="red")
    table.add_column("Banner", style="dim", overflow="fold", max_width=50)
    
    # Add a row per service
    for svc in services:
        table.add_row(
            str(svc.port),
            svc.service,
            svc.product or "—",         # show dash if None
            svc.version or "—",
            svc.banner or "—"
        )
    
    console.print()
    console.print(table)


def main():
    """Main entry point - orchestrates the entire scan."""
    print_banner()
    args = parse_arguments()
    
    target = args.target
    
    # Phase 1: Port Scanning
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
    
    # Phase 2: Service Detection
    console.print(f"\n[bold]Phase 2:[/bold] Detecting services on {len(open_ports)} open ports...")
    
    services = []
    for port in open_ports:
        console.print(f"  [dim]Probing port {port}...[/dim]")
        info = detect_service(target, port, timeout=args.timeout * 3)
        services.append(info)
    
    # Phase 3: Display
    display_results(target, services)
    
    console.print(f"\n[bold green]✓ Scan complete![/bold green]\n")


if __name__ == "__main__":
    main()