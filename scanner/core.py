"""
VulnScan Core - Async vulnerability scanning engine
"""
import asyncio
import socket
import ssl
import time
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


@dataclass
class ScanTarget:
    host: str
    ports: List[int] = field(default_factory=lambda: [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017])
    timeout: float = 2.0


@dataclass
class PortResult:
    port: int
    state: str  # open / closed / filtered
    service: str
    banner: Optional[str] = None
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    ip: str
    scan_start: datetime
    scan_end: Optional[datetime] = None
    ports: List[PortResult] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    os_guess: Optional[str] = None
    error: Optional[str] = None

    @property
    def duration_seconds(self):
        if self.scan_end:
            return (self.scan_end - self.scan_start).total_seconds()
        return 0

    @property
    def open_ports(self):
        return [p for p in self.ports if p.state == "open"]

    @property
    def risk_score(self):
        """0–100 composite risk score."""
        score = 0
        severity_map = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
        for v in self.vulnerabilities:
            score += severity_map.get(v.get("severity", "info"), 0)
        # Penalise dangerous open ports
        dangerous = {21, 23, 3389, 5432, 27017}
        for p in self.open_ports:
            if p.port in dangerous:
                score += 5
        return min(score, 100)


COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


async def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt a quick banner grab on an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            # Send a minimal HTTP probe for web ports
            if port in (80, 8080):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            banner = await asyncio.wait_for(reader.read(256), timeout=1.5)
            return banner.decode(errors="replace").strip()[:200]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None


async def check_port(host: str, port: int, timeout: float) -> PortResult:
    """Check a single port asynchronously."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner = await grab_banner(host, port, timeout)
        return PortResult(
            port=port,
            state="open",
            service=COMMON_SERVICES.get(port, "unknown"),
            banner=banner,
            latency_ms=round(latency, 2),
        )
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return PortResult(port=port, state="closed", service=COMMON_SERVICES.get(port, "unknown"))
    except OSError:
        return PortResult(port=port, state="filtered", service=COMMON_SERVICES.get(port, "unknown"))


async def resolve_host(host: str) -> str:
    """Resolve hostname to IP."""
    loop = asyncio.get_event_loop()
    try:
        info = await loop.getaddrinfo(host, None)
        return info[0][4][0]
    except Exception:
        return host


async def run_scan(target: ScanTarget, progress_callback=None) -> ScanResult:
    """Run a full async port scan against the target."""
    scan_start = datetime.now()
    ip = await resolve_host(target.host)

    result = ScanResult(target=target.host, ip=ip, scan_start=scan_start)

    semaphore = asyncio.Semaphore(100)  # max 100 concurrent connections

    async def limited_check(port):
        async with semaphore:
            pr = await check_port(ip, port, target.timeout)
            if progress_callback:
                await progress_callback(port, pr)
            return pr

    tasks = [limited_check(p) for p in target.ports]
    port_results = await asyncio.gather(*tasks, return_exceptions=True)

    for pr in port_results:
        if isinstance(pr, PortResult):
            result.ports.append(pr)

    result.scan_end = datetime.now()
    return result
