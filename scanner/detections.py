"""
VulnScan Detections - Vulnerability detection rules
"""
from typing import List, Dict
from .core import ScanResult, PortResult


# ─────────────────────────────────────────────
#  Detection rule format:
#  {
#    "id":          str   (CVE or internal ID)
#    "title":       str
#    "severity":    critical | high | medium | low | info
#    "description": str
#    "remediation": str
#    "references":  List[str]
#  }
# ─────────────────────────────────────────────

def detect_telnet(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.port == 23 and p.state == "open":
            findings.append({
                "id": "VULN-001",
                "title": "Telnet Service Exposed",
                "severity": "critical",
                "port": 23,
                "description": "Telnet transmits all data, including credentials, in plaintext.",
                "remediation": "Disable Telnet immediately. Replace with SSH.",
                "references": ["https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=telnet"],
            })
    return findings


def detect_ftp_anonymous(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.port == 21 and p.state == "open":
            severity = "high"
            desc = "FTP service is running. FTP transfers credentials in plaintext."
            if p.banner and "anonymous" in p.banner.lower():
                severity = "critical"
                desc += " Anonymous login appears to be enabled."
            findings.append({
                "id": "VULN-002",
                "title": "FTP Service Exposed",
                "severity": severity,
                "port": 21,
                "description": desc,
                "remediation": "Replace FTP with SFTP or FTPS. Disable anonymous access.",
                "references": ["https://nvd.nist.gov/vuln/search/results?query=ftp+anonymous"],
            })
    return findings


def detect_rdp_exposed(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.port == 3389 and p.state == "open":
            findings.append({
                "id": "VULN-003",
                "title": "RDP Exposed to Network",
                "severity": "high",
                "port": 3389,
                "description": "Remote Desktop Protocol is accessible. RDP has a history of critical vulnerabilities (BlueKeep, DejaBlue).",
                "remediation": "Restrict RDP access via firewall. Use VPN + NLA. Apply all patches.",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
            })
    return findings


def detect_unencrypted_db(ports: List[PortResult]) -> List[Dict]:
    findings = []
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
    for p in ports:
        if p.port in db_ports and p.state == "open":
            findings.append({
                "id": f"VULN-DB-{p.port}",
                "title": f"{db_ports[p.port]} Exposed Without Firewall",
                "severity": "critical",
                "port": p.port,
                "description": f"{db_ports[p.port]} port {p.port} is publicly reachable. Database services should never be internet-facing.",
                "remediation": "Bind database to 127.0.0.1 or restrict via firewall rules. Use strong auth.",
                "references": ["https://owasp.org/www-project-top-ten/"],
            })
    return findings


def detect_http_no_https(ports: List[PortResult]) -> List[Dict]:
    findings = []
    open_ports = {p.port for p in ports if p.state == "open"}
    if 80 in open_ports and 443 not in open_ports:
        findings.append({
            "id": "VULN-005",
            "title": "HTTP Without HTTPS",
            "severity": "medium",
            "port": 80,
            "description": "Web service running on plain HTTP with no HTTPS detected. Traffic is unencrypted.",
            "remediation": "Obtain a TLS certificate (Let's Encrypt is free). Redirect HTTP → HTTPS.",
            "references": ["https://letsencrypt.org"],
        })
    return findings


def detect_smtp_open_relay(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.port == 25 and p.state == "open":
            findings.append({
                "id": "VULN-006",
                "title": "SMTP Port Exposed",
                "severity": "medium",
                "port": 25,
                "description": "SMTP port 25 is accessible. May allow open relay or be exploited for spam.",
                "remediation": "Restrict port 25 to known mail servers. Enforce STARTTLS and SPF/DKIM/DMARC.",
                "references": ["https://www.rfc-editor.org/rfc/rfc5321"],
            })
    return findings


def detect_default_banners(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.banner and p.state == "open":
            banner_lower = p.banner.lower()
            version_keywords = ["apache/", "nginx/", "openssh_", "microsoft-iis/", "vsftpd/", "proftpd/"]
            for kw in version_keywords:
                if kw in banner_lower:
                    findings.append({
                        "id": "VULN-007",
                        "title": f"Version Info Disclosed on Port {p.port}",
                        "severity": "low",
                        "port": p.port,
                        "description": f"Server banner exposes software version: '{p.banner[:80]}'. Enables targeted attacks.",
                        "remediation": "Suppress version disclosure in service configuration (e.g. ServerTokens Prod for Apache).",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
                    })
                    break
    return findings


ALL_DETECTORS = [
    detect_telnet,
    detect_ftp_anonymous,
    detect_rdp_exposed,
    detect_unencrypted_db,
    detect_http_no_https,
    detect_smtp_open_relay,
    detect_default_banners,
]


def run_detections(result: ScanResult) -> ScanResult:
    """Run all detection rules against a scan result."""
    all_findings = []
    for detector in ALL_DETECTORS:
        try:
            all_findings.extend(detector(result.ports))
        except Exception as e:
            pass  # Never let a detection rule crash the scan
    result.vulnerabilities = all_findings
    return result
