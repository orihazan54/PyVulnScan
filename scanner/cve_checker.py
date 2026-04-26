"""
CVE Checker Module
------------------
Queries the NVD (National Vulnerability Database) API to find known
CVEs for detected services and versions.
"""

import time
import requests
from dataclasses import dataclass, field
from typing import List, Optional


# NVD API endpoint - the official US government vulnerability database
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Without an API key we're limited to 5 requests per 30 seconds
# Adding a small delay between requests keeps us safely under the limit
REQUEST_DELAY = 6.0  # seconds


@dataclass
class CVE:
    """Represents a single CVE entry."""
    id: str                              # e.g., "CVE-2018-15473"
    description: str                     # Human-readable description
    severity: str = "UNKNOWN"            # LOW / MEDIUM / HIGH / CRITICAL
    score: float = 0.0                   # CVSS score 0.0 - 10.0
    
    def __str__(self) -> str:
        return f"{self.id} [{self.severity} {self.score}] - {self.description[:80]}..."


@dataclass
class CVEResult:
    """Container for all CVEs found for a single product/version."""
    product: str
    version: str
    cves: List[CVE] = field(default_factory=list)
    error: Optional[str] = None


def severity_from_score(score: float) -> str:
    """
    Maps a CVSS score to a severity rating.
    
    Based on the official CVSS v3.1 scoring guide.
    """
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "UNKNOWN"


def search_cves(product: str, version: str, max_results: int = 10) -> CVEResult:
    """
    Searches NVD for CVEs matching a product and version.
    
    Uses progressive fallback: tries exact version first,
    then major version, then product alone.
    
    Args:
        product: Product name, e.g., "OpenSSH"
        version: Version string, e.g., "6.6.1p1"
        max_results: Maximum number of CVEs to return
    
    Returns:
        CVEResult containing the list of CVEs found.
    """
    result = CVEResult(product=product, version=version)
    
    # Build progressive fallback search queries
    # Extract major version (e.g., "6.6.1p1" -> "6.6", "2.4.41" -> "2.4")
    version_parts = version.split(".")
    major_version = ".".join(version_parts[:2]) if len(version_parts) >= 2 else version
    
    search_queries = [
        f"{product} {version}",           # Most specific: "OpenSSH 6.6.1p1"
        f"{product} {major_version}",     # Less specific: "OpenSSH 6.6"
        product,                          # Least specific: "OpenSSH"
    ]
    
    # NVD requires a User-Agent header for some clients
    headers = {
        "User-Agent": "PyVulnScan/1.0"
    }
    
    vulnerabilities = []
    
    for query in search_queries:
        params = {
            "keywordSearch": query,
            "resultsPerPage": max_results,
        }
        
        try:
            response = requests.get(
                NVD_API_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # If we got results, stop trying broader queries
            if vulnerabilities:
                print(f"  [debug] Found {len(vulnerabilities)} results with query: '{query}'")
                break
            else:
                print(f"  [debug] No results for query: '{query}', trying broader...")
        
        except requests.exceptions.RequestException as e:
            result.error = f"API request failed: {e}"
            return result
        except ValueError as e:
            result.error = f"Failed to parse response: {e}"
            return result
        
        # Rate limit: small wait between fallback queries
        time.sleep(2)
    
    if not vulnerabilities:
        return result
    
    # Parse the results
    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")
        
        # Get English description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Get CVSS score (try v3.1, v3.0, then v2)
        score = 0.0
        metrics = cve_data.get("metrics", {})
        
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        
        cve = CVE(
            id=cve_id,
            description=description,
            severity=severity_from_score(score),
            score=score
        )
        result.cves.append(cve)
    
    # Sort by score (highest first)
    result.cves.sort(key=lambda c: c.score, reverse=True)
    
    return result

def check_services_for_cves(services: list) -> List[CVEResult]:
    """
    Checks each detected service against NVD for known CVEs.
    
    Args:
        services: List of ServiceInfo objects from service_detector
    
    Returns:
        List of CVEResult objects, one per service that had product/version info.
    """
    results = []
    
    # Filter to only services where we have both product and version
    # No point querying NVD without that info
    valid_services = [s for s in services if s.product and s.version]
    
    if not valid_services:
        return results
    
    for i, service in enumerate(valid_services):
        # Rate limiting - wait between requests except for the first one
        if i > 0:
            time.sleep(REQUEST_DELAY)
        
        cve_result = search_cves(service.product, service.version)
        results.append(cve_result)
    
    return results


if __name__ == "__main__":
    # Test with a known-vulnerable version
    print("Testing CVE Checker with OpenSSH 6.6.1p1...\n")
    
    result = search_cves("OpenSSH", "6.6.1p1", max_results=5)
    
    if result.error:
        print(f"Error: {result.error}")
    else:
        print(f"Found {len(result.cves)} CVEs for {result.product} {result.version}\n")
        for cve in result.cves:
            print(f"  {cve}")