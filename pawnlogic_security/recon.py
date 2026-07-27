"""Real reconnaissance operations.

Every function here is a thin adapter over stdlib capabilities. Nothing in this
module downloads binaries, wordlists, browsers, or containers. Each function
returns structured data the caller can format into a string for the model.

DNS uses the local resolver. TLS connects once to read the certificate. HTTP
uses urllib with a short timeout. Port scanning uses socket.connect_ex with the
scope's concurrency and request budgets applied.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from http.client import HTTPConnection, HTTPResponse, HTTPSConnection
from typing import Any, cast

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
    address: str = ""
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


@dataclass(frozen=True, slots=True)
class ScopedTarget:
    """One hostname and the exact DNS answers approved for connection."""

    hostname: str
    dns: DnsResult
    addresses: tuple[str, ...] = ()
    error: str = ""


BudgetConsumer = Callable[[int], None]


class _PinnedHTTPConnection(HTTPConnection):
    """HTTP connection whose socket endpoint is an already-approved IP."""

    def __init__(
        self,
        hostname: str,
        address: str,
        *,
        port: int,
        timeout: float,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout)
        self._approved_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._approved_address, self.port),
            timeout=self.timeout,
            source_address=None,
        )


class _PinnedHTTPSConnection(HTTPSConnection):
    """HTTPS connection preserving hostname SNI over an approved IP socket."""

    def __init__(
        self,
        hostname: str,
        address: str,
        *,
        port: int,
        timeout: float,
    ) -> None:
        context = ssl.create_default_context()
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=context,
        )
        self._approved_address = address
        self._tls_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._approved_address, self.port),
            timeout=self.timeout,
            source_address=None,
        )
        self.sock = self._tls_context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


def _resolve_dns(hostname: str, timeout: float = 5.0) -> DnsResult:
    """Resolve a hostname to IP addresses using the local resolver."""
    try:
        infos = socket.getaddrinfo(
            hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        addresses = sorted({str(info[4][0]) for info in infos})
        return DnsResult(hostname=hostname, addresses=tuple(addresses))
    except (socket.gaierror, socket.herror, OSError) as error:
        return DnsResult(hostname=hostname, error=str(error))


def _inspect_tls(
    hostname: str,
    port: int = 443,
    *,
    address: str,
    timeout: float = 5.0,
) -> TlsCertResult:
    """Connect once and read the TLS certificate."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = cast(dict[str, Any], ssock.getpeercert())
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                return TlsCertResult(
                    hostname=hostname,
                    port=port,
                    subject=subject.get("commonName", ""),
                    issuer=str(
                        issuer.get(
                            "organizationName",
                            issuer.get("commonName", ""),
                        )
                        or ""
                    ),
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
    hostname: str,
    port: int = 443,
    *,
    address: str,
    use_https: bool = True,
    timeout: float = 5.0,
) -> HttpHeadersResult:
    """Fetch HTTP headers while connecting to a previously checked IP."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{hostname}:{port}/"
    try:
        conn: HTTPConnection
        if use_https:
            conn = _PinnedHTTPSConnection(
                hostname,
                address,
                port=port,
                timeout=timeout,
            )
        else:
            conn = _PinnedHTTPConnection(
                hostname,
                address,
                port=port,
                timeout=timeout,
            )
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


def resolve_scoped_target(
    target: str,
    scope: EngagementScope,
    now: float,
    *,
    timeout: float = 5.0,
    consume_requests: BudgetConsumer | None = None,
) -> ScopedTarget:
    """Resolve once and require every answer to remain inside Scope."""
    from pawnlogic_security.scope import authorize as scope_authorize

    decision = scope_authorize(scope, target, now)
    if not decision.authorized:
        empty = DnsResult(hostname=decision.normalized_target or target)
        return ScopedTarget(
            hostname=decision.normalized_target or target,
            dns=empty,
            error=decision.reason,
        )
    if consume_requests is not None:
        try:
            consume_requests(1)
        except PermissionError as error:
            empty = DnsResult(hostname=decision.normalized_target)
            return ScopedTarget(
                hostname=decision.normalized_target,
                dns=empty,
                error=str(error),
            )
    dns = _resolve_dns(decision.normalized_target, timeout=timeout)
    if dns.error:
        return ScopedTarget(hostname=decision.normalized_target, dns=dns, error=dns.error)
    if not dns.addresses:
        return ScopedTarget(
            hostname=decision.normalized_target,
            dns=dns,
            error="DNS returned no addresses",
        )
    errors: list[str] = []
    for address in dns.addresses:
        address_decision = scope_authorize(scope, address, now)
        if not address_decision.authorized:
            errors.append(
                f"resolved address {address} not in scope: {address_decision.reason}"
            )
    if errors:
        return ScopedTarget(
            hostname=decision.normalized_target,
            dns=dns,
            error="; ".join(errors),
        )
    return ScopedTarget(
        hostname=decision.normalized_target,
        dns=dns,
        addresses=dns.addresses,
    )


def passive_recon(
    target: str,
    scope: EngagementScope,
    now: float,
    *,
    timeout: float = 5.0,
    resolved: ScopedTarget | None = None,
    consume_requests: BudgetConsumer | None = None,
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

    checked = resolved or resolve_scoped_target(
        target,
        scope,
        now,
        timeout=timeout,
        consume_requests=consume_requests,
    )
    dns = checked.dns
    if checked.error:
        return PassiveReconResult(
            target=target,
            dns=dns,
            errors=(checked.error,),
        )
    scope_addresses = list(checked.addresses)
    redirect_hops: list[str] = []
    address = checked.addresses[0]

    tls: TlsCertResult | None = None
    http: HttpHeadersResult | None = None
    if scope.allows_port(443):
        if consume_requests is not None:
            try:
                consume_requests(1)
            except PermissionError as error:
                return PassiveReconResult(
                    target=target,
                    dns=dns,
                    scope_addresses=tuple(scope_addresses),
                    errors=(str(error),),
                )
        tls = _inspect_tls(hostname, address=address, timeout=timeout)
        if tls.error:
            errors.append(f"tls: {tls.error}")

        if consume_requests is not None:
            try:
                consume_requests(1)
            except PermissionError as error:
                return PassiveReconResult(
                    target=target,
                    dns=dns,
                    tls=tls,
                    scope_addresses=tuple(scope_addresses),
                    errors=tuple([*errors, str(error)]),
                )
        http = _http_headers(hostname, address=address, timeout=timeout)

    if (http is None or http.error) and scope.allows_port(80):
        if consume_requests is not None:
            try:
                consume_requests(1)
            except PermissionError as error:
                return PassiveReconResult(
                    target=target,
                    dns=dns,
                    tls=tls,
                    http=http,
                    scope_addresses=tuple(scope_addresses),
                    errors=tuple([*errors, str(error)]),
                )
        http = _http_headers(
            hostname,
            port=80,
            address=address,
            use_https=False,
            timeout=timeout,
        )
    if http is None:
        errors.append("scope authorizes neither port 443 nor port 80")
    elif http.error:
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
    resolved: ScopedTarget | None = None,
    consume_requests: BudgetConsumer | None = None,
) -> tuple[PortResult, ...]:
    """Scan ports permitted by the scope's port ranges and request budget.

    Returns a tuple of open/closed/error results, ordered by port number.
    The caller formats them into a model-facing string.
    """
    from pawnlogic_security.scope import authorize as scope_authorize

    decision = scope_authorize(scope, target, now)
    if not decision.authorized:
        return (PortResult(port=0, state="error", error=decision.reason),)

    if not scope.allow_active or not scope.allows_action("active"):
        return (
            PortResult(
                port=0, state="error", error="scope does not permit active operations"
            ),
        )

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
        return (
            PortResult(
                port=0,
                state="error",
                error="scope does not explicitly authorize any ports",
            ),
        )

    checked = resolved or resolve_scoped_target(
        target,
        scope,
        now,
        timeout=timeout,
        consume_requests=consume_requests,
    )
    if checked.error:
        return (PortResult(port=0, state="error", error=checked.error),)
    if consume_requests is not None:
        try:
            consume_requests(len(ports) * len(checked.addresses))
        except PermissionError as error:
            return (PortResult(port=0, state="error", error=str(error)),)

    # Apply concurrency cap.
    effective_workers = max_workers
    if scope.max_concurrency > 0:
        effective_workers = min(effective_workers, scope.max_concurrency)

    results: list[PortResult] = []

    def _scan_one(address: str, port: int) -> PortResult:
        try:
            family = (
                socket.AF_INET6
                if ipaddress.ip_address(address).version == 6
                else socket.AF_INET
            )
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((address, port))
            if result == 0:
                service = _guess_service(port)
                return PortResult(
                    port=port,
                    state="open",
                    address=address,
                    service=service,
                )
            return PortResult(port=port, state="closed", address=address)
        except OSError as error:
            return PortResult(
                port=port,
                state="error",
                address=address,
                error=str(error),
            )

    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        futures = {
            executor.submit(_scan_one, address, port): (address, port)
            for address in checked.addresses
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    return tuple(sorted(results, key=lambda r: (r.address, r.port)))


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
    "ScopedTarget",
    "TlsCertResult",
    "active_port_scan",
    "passive_recon",
    "resolve_scoped_target",
]
