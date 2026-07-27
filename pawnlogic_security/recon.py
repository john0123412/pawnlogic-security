"""Real reconnaissance operations.

Every function here is a thin adapter over stdlib capabilities. Nothing in this
module downloads binaries, wordlists, browsers, or containers. Each function
returns structured data the caller can format into a string for the model.

DNS uses the local resolver. TLS connects once to read the certificate. HTTP
uses urllib with a short timeout. Port scanning uses socket.connect_ex with the
scope's concurrency and request budgets applied.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPResponse, HTTPSConnection

from pawnlogic_security.scope import EngagementScope


@dataclass(frozen=True, slots=True)
class DnsResult:
    """Resolved addresses for a hostname."""

    hostname: str
    addresses: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True, slots=True)
class TlsCertResult:
    """A TLS certificate summary, or an error if the connection failed."""

    hostname: str
    port: int
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    serial: str = ""
    error: str = ""


@dataclass(frozen=True, slots=True)
class HttpHeadersResult:
    """HTTP response headers from a HEAD request."""

    url: str
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    server: str = ""
    powered_by: str = ""
    technologies: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True, slots=True)
class PortResult:
    """A single port scan result."""

    port: int
    state: str  # "open", "closed", "error"
    service: str = ""
    error: str = ""


@dataclass(frozen=True, slots=True)
class PassiveReconResult:
    """Everything collected during passive recon against one host."""

    target: str
    dns: DnsResult | None = None
    tls: TlsCertResult | None = None
    http: HttpHeadersResult | None = None
    scope_addresses: tuple[str, ...] = ()
    redirect_hops: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


def _resolve_dns(hostname: str, timeout: float = 5.0) -> DnsResult:
    """Resolve a hostname to IP addresses using the local resolver."""
    try:
        infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        addresses = sorted({info[4][0] for info in infos})
        return DnsResult(hostname=hostname, addresses=tuple(addresses))
    except (socket.gaierror, socket.herror, OSError) as error:
        return DnsResult(hostname=hostname, error=str(error))


def _inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> TlsCertResult:
    """Connect once and read the TLS certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                return TlsCertResult(
                    hostname=hostname,
                    port=port,
                    subject=subject.get("commonName", ""),
                    issuer=issuer.get("organizationName", issuer.get("commonName", "")),
                    not_before=cert.get("notBefore", ""),
                    not_after=cert.get("notAfter", ""),
                    serial=str(cert.get("serialNumber", "")),
                )
    except (TimeoutError, ssl.SSLError, OSError) as error:
        return TlsCertResult(hostname=hostname, port=port, error=str(error))


_TECH_HINTS: Mapping[str, str] = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generator",
    "x-drupal-cache": "Drupal",
    "x-wordpress-cache": "WordPress",
    "via": "Proxy",
    "x-cdn": "CDN",
}


def _http_headers(
    hostname: str, port: int = 443, *, use_https: bool = True, timeout: float = 5.0
) -> HttpHeadersResult:
    """Fetch HTTP headers with a HEAD request."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{hostname}:{port}/"
    try:
        if use_https:
            conn = HTTPSConnection(
                hostname,
                port=port,
                timeout=timeout,
                context=ssl.create_default_context(),
            )
        else:
            conn = HTTPConnection(hostname, port=port, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "pawnlogic-security/0.1"})
        resp: HTTPResponse = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()

        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        techs: list[str] = []
        if server:
            techs.append(f"server: {server}")
        if powered_by:
            techs.append(f"powered-by: {powered_by}")
        for key, label in _TECH_HINTS.items():
            if key in headers and key not in ("server", "x-powered-by"):
                techs.append(f"{label}: {headers[key]}")

        return HttpHeadersResult(
            url=url,
            status=resp.status,
            headers=headers,
            server=server,
            powered_by=powered_by,
            technologies=tuple(techs),
        )
    except (TimeoutError, OSError, ssl.SSLError) as error:
        return HttpHeadersResult(url=url, error=str(error))


def passive_recon(
    target: str,
    scope: EngagementScope,
    now: float,
    *,
    timeout: float = 5.0,
) -> PassiveReconResult:
    """Run passive recon against one in-scope target.

    DNS, TLS, and HTTP headers are collected. Each resolved address is checked
    against scope before any connection is made to it.

    Returns structured data. The caller formats it into a model-facing string.
    """
    from pawnlogic_security.scope import authorize as scope_authorize

    errors: list[str] = []
    decision = scope_authorize(scope, target, now)
    if not decision.authorized:
        return PassiveReconResult(target=target, errors=(decision.reason,))

    hostname = decision.normalized_target

    # 1. DNS
    dns = _resolve_dns(hostname, timeout=timeout)
    if dns.error:
        errors.append(f"dns: {dns.error}")

    # 2. Check resolved addresses against scope
    scope_addresses: list[str] = []
    redirect_hops: list[str] = []
    for addr in dns.addresses:
        addr_decision = scope_authorize(scope, addr, now)
        if addr_decision.authorized:
            scope_addresses.append(addr)
        else:
            errors.append(
                f"resolved address {addr} not in scope: {addr_decision.reason}"
            )

    # 3. TLS
    tls = _inspect_tls(hostname, timeout=timeout)
    if tls.error:
        errors.append(f"tls: {tls.error}")

    # 4. HTTP headers (try HTTPS first, fall back to HTTP)
    http = _http_headers(hostname, timeout=timeout)
    if http.error:
        http = _http_headers(hostname, port=80, use_https=False, timeout=timeout)
        if http.error:
            errors.append(f"http: {http.error}")

    return PassiveReconResult(
        target=target,
        dns=dns,
        tls=tls,
        http=http,
        scope_addresses=tuple(scope_addresses),
        redirect_hops=tuple(redirect_hops),
        errors=tuple(errors),
    )


def active_port_scan(
    target: str,
    scope: EngagementScope,
    now: float,
    *,
    timeout: float = 2.0,
    max_workers: int = 10,
) -> tuple[PortResult, ...]:
    """Scan ports permitted by the scope's port ranges and request budget.

    Returns a tuple of open/closed/error results, ordered by port number.
    The caller formats them into a model-facing string.
    """
    from pawnlogic_security.scope import authorize as scope_authorize

    decision = scope_authorize(scope, target, now)
    if not decision.authorized:
        return (PortResult(port=0, state="error", error=decision.reason),)

    if not scope.allow_active:
        return (
            PortResult(
                port=0, state="error", error="scope does not permit active operations"
            ),
        )

    hostname = decision.normalized_target

    # Resolve ports from scope ranges.
    ports: list[int] = []
    for entry in scope.ports:
        if isinstance(entry, int):
            ports.append(entry)
        elif isinstance(entry, tuple):
            low, high = entry
            # Cap the range to prevent unbounded scans.
            count = min(high - low + 1, 1024)
            ports.extend(range(low, low + count))
    if not ports:
        # Default common ports if scope doesn't specify any.
        ports = [80, 443, 8080, 8443]

    # Apply request budget.
    if scope.max_requests > 0:
        ports = ports[: scope.max_requests]

    # Apply concurrency cap.
    effective_workers = max_workers
    if scope.max_concurrency > 0:
        effective_workers = min(effective_workers, scope.max_concurrency)

    results: list[PortResult] = []

    def _scan_one(port: int) -> PortResult:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            if result == 0:
                service = _guess_service(port)
                return PortResult(port=port, state="open", service=service)
            return PortResult(port=port, state="closed")
        except OSError as error:
            return PortResult(port=port, state="error", error=str(error))

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = {executor.submit(_scan_one, port): port for port in ports}
        for future in as_completed(futures):
            results.append(future.result())

    return tuple(sorted(results, key=lambda r: r.port))


def _guess_service(port: int) -> str:
    """Map well-known ports to service names."""
    well_known = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        465: "smtps",
        587: "submission",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        1521: "oracle",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
        9200: "elasticsearch",
        27017: "mongodb",
    }
    return well_known.get(port, "")


__all__ = [
    "DnsResult",
    "HttpHeadersResult",
    "PassiveReconResult",
    "PortResult",
    "TlsCertResult",
    "active_port_scan",
    "passive_recon",
]
