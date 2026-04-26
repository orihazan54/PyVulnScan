"""
HTML Reporter Module
--------------------
Generates a beautiful HTML report from scan results using Jinja2 templating.
"""

import os
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


# Get the directory where this file lives, then find the templates folder
TEMPLATES_DIR = Path(__file__).parent / "templates"


def generate_html_report(
    target: str,
    services: list,
    cve_results: list,
    output_path: str = "report.html"
) -> str:
    """
    Generates an HTML report from scan results.
    
    Args:
        target: The scanned target hostname/IP
        services: List of ServiceInfo objects from service_detector
        cve_results: List of CVEResult objects from cve_checker
        output_path: Where to save the HTML file
    
    Returns:
        Absolute path to the generated report.
    """
    # Set up Jinja2 environment - tells it where to find templates
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=True   # Auto-escape HTML to prevent XSS in banners
    )
    
    # Load our template
    template = env.get_template("report.html")
    
    # Calculate summary statistics
    open_ports_count = len(services)
    services_with_version_count = sum(1 for s in services if s.product)
    total_cves = sum(len(r.cves) for r in cve_results) if cve_results else 0
    critical_cves = sum(
        1 for r in cve_results for cve in r.cves
        if cve.severity == "CRITICAL"
    ) if cve_results else 0
    
    # Render the template with our data
    html_content = template.render(
        target=target,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        services=services,
        cve_results=cve_results,
        open_ports_count=open_ports_count,
        services_with_version_count=services_with_version_count,
        total_cves=total_cves,
        critical_cves=critical_cves,
    )
    
    # Write to file
    output_file = Path(output_path).resolve()
    output_file.write_text(html_content, encoding="utf-8")
    
    return str(output_file)


if __name__ == "__main__":
    # Quick test with dummy data
    from dataclasses import dataclass
    
    @dataclass
    class DummyService:
        port: int
        service: str
        product: str = None
        version: str = None
        banner: str = None
    
    services = [
        DummyService(22, "SSH", "OpenSSH", "6.6.1p1", "SSH-2.0-OpenSSH_6.6.1p1"),
        DummyService(80, "HTTP", "Apache", "2.4.7", "Apache/2.4.7 (Ubuntu)"),
    ]
    
    output = generate_html_report("test.example.com", services, [])
    print(f"Report generated: {output}")