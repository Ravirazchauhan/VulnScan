# 🔍 VulnScan

> A fast, async Python vulnerability scanner with a rich terminal UI and HTML/JSON reporting.

![Python](https://img.shields.io/badge/python-3.1+-blue?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Async](https://img.shields.io/badge/async-asyncio-purple?style=flat-square)

**By — RAVI CHAUHAN** &nbsp;|&nbsp; 🔗 [github.com/Ravirazchauhan](https://github.com/Ravirazchauhan)

---

## ✨ Features

| Feature | Detail |
|---|---|
| ⚡ **Async Engine** | Scans 100 ports concurrently per target via `asyncio` |
| 🛡️ **Detection Rules** | 7 built-in rules: Telnet, FTP, RDP, exposed DBs, HTTP-only, SMTP, banner disclosure |
| 📊 **Risk Scoring** | Composite 0–100 risk score per target |
| 🖥️ **Rich Terminal UI** | Colour-coded tables, progress bar, live output via `rich` |
| 📄 **HTML Reports** | Dark-themed, self-contained HTML report per scan |
| 📦 **JSON Export** | Machine-readable structured JSON for CI/CD pipelines |
| 🌐 **CIDR Support** | Scan entire subnets — `192.168.1.0/24` expands automatically |
| 🎯 **Banner Grabbing** | Detects software + version disclosure on open ports |

---

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/Ravirazchauhan/vulnscan.git
cd vulnscan
pip install -r requirements.txt

# Scan a single host
python main.py 192.168.1.1

# Scan with custom ports
python main.py example.com --ports 22 80 443 8080 8443

# Scan a subnet and export reports
python main.py 192.168.1.0/24 --output reports/scan --json

# Multiple targets with fast timeout
python main.py 10.0.0.1 10.0.0.2 10.0.0.3 --timeout 1.0 --output results/audit
```

---

## 📁 Project Structure

```
vulnscan/
├── main.py                  # CLI entry point
├── requirements.txt
├── scanner/
│   ├── __init__.py
│   ├── core.py              # Async port scanner + data models
│   └── detections.py        # Vulnerability detection rules
├── reports/
│   ├── __init__.py
│   └── generator.py         # HTML + JSON report generation
└── utils/
    └── __init__.py
```

---

## 🛡️ Detection Rules

| ID | Finding | Severity |
|---|---|---|
| VULN-001 | Telnet Service Exposed | 🔴 Critical |
| VULN-002 | FTP Service / Anonymous Login | 🔴 Critical / 🟠 High |
| VULN-003 | RDP Exposed to Network | 🟠 High |
| VULN-DB-* | Database port publicly reachable | 🔴 Critical |
| VULN-005 | HTTP without HTTPS | 🟡 Medium |
| VULN-006 | SMTP Port Exposed | 🟡 Medium |
| VULN-007 | Version Info Banner Disclosure | 🟢 Low |

---

## ➕ Adding Detection Rules

Create a new function in `scanner/detections.py` and add it to `ALL_DETECTORS`:

```python
def detect_my_rule(ports: List[PortResult]) -> List[Dict]:
    findings = []
    for p in ports:
        if p.port == 8080 and p.state == "open":
            findings.append({
                "id": "VULN-CUSTOM-001",
                "title": "My Custom Finding",
                "severity": "medium",          # critical | high | medium | low | info
                "port": p.port,
                "description": "Explain the risk.",
                "remediation": "Explain the fix.",
                "references": ["https://example.com"],
            })
    return findings

# Add to the list at the bottom of detections.py:
ALL_DETECTORS = [..., detect_my_rule]
```

---

## ⚙️ CLI Reference

```
python main.py <targets> [options]

Arguments:
  targets            One or more hosts or CIDR ranges

Options:
  --ports            Space-separated port list (default: 17 common ports)
  --timeout          Connection timeout in seconds (default: 2.0)
  --output, -o       Report output path prefix (e.g. reports/scan)
  --json             Also export a JSON report alongside HTML
```

---

## ⚠️ Legal Notice

> This tool is intended **for authorised security testing only**.  
> Only scan systems you own or have explicit written permission to test.  
> Unauthorised scanning may be illegal in your jurisdiction.

---

## 📝 License

MIT — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**RAVI CHAUHAN**  
🔗 GitHub: [https://github.com/Ravirazchauhan](https://github.com/Ravirazchauhan)
