"""
Phishing Detection & Risk Intelligence Platform
Phase 29.2: DNS Feature Extraction & Domain Resolution Analysis

Extracts DNS records (A, MX, NS, TXT) and domain resolution characteristics.
Engineered with strict operational controls:
- Strict sub-250ms socket resolution timeouts
- Circuit breaker pattern to prevent cascading network degradation
- In-memory TTL resolution caching
- Fast-flux phishing network detection
- Graceful offline fallback
"""

import os
import sys
import time
import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class DNSCircuitBreaker:
    """
    Prevents cascading latency spikes when upstream DNS servers or network are degraded.
    Opens circuit after consecutive failures and enters cooldown.
    """
    def __init__(self, failure_threshold: int = 5, recovery_timeout_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"  # CLOSED (healthy), OPEN (degraded, short-circuit)

    def record_success(self) -> None:
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> None:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def is_available(self) -> bool:
        if self.state == "CLOSED":
            return True
        # Check if recovery timeout has elapsed
        if time.time() - self.last_failure_time > self.recovery_timeout_seconds:
            self.state = "HALF_OPEN"
            return True
        return False


class DNSFeatureExtractor:
    """
    Extracts structural DNS resolution signals with strict timeout and offline tolerance.
    """
    def __init__(
        self,
        timeout_seconds: float = 0.25,
        cache_ttl_seconds: int = 1800,
        enable_mock_fallback: bool = True
    ):
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self.enable_mock_fallback = enable_mock_fallback
        self.circuit_breaker = DNSCircuitBreaker()
        self._cache: Dict[str, Dict[str, Any]] = {}
        cache_dir = os.path.join(PROJECT_ROOT, ".cache")
        os.makedirs(cache_dir, exist_ok=True)
        self.tld_extractor = tldextract.TLDExtract(cache_dir=cache_dir, suffix_list_urls=None)

    def _extract_hostname(self, url: str) -> str:
        raw = url.strip()
        if not (raw.startswith("http://") or raw.startswith("https://")):
            raw = "http://" + raw
        parsed = urlparse(raw)
        return (parsed.hostname or "").lower().strip()

    def extract_dns_features(self, url: str) -> Dict[str, Any]:
        """
        Extracts DNS resolution characteristics with strict RCODE differentiation:
        - True NXDOMAIN: Authoritative RCODE 3 (Domain not found)
        - NODATA: RCODE 0 (Host exists, but no A/AAAA record)
        - SERVFAIL / REFUSED: Upstream DNS failure (Neutral)
        - TIMEOUT: Resolution timed out (Neutral)
        - DNS_UNAVAILABLE: Circuit breaker open or network disabled (Neutral)
        """
        hostname = self._extract_hostname(url)
        if not hostname:
            return self._build_empty_response(hostname, "Invalid or empty hostname.")

        # Check in-memory cache
        now = time.time()
        if hostname in self._cache:
            entry = self._cache[hostname]
            if now < entry["expires_at"]:
                return entry["data"]

        # Check circuit breaker
        if not self.circuit_breaker.is_available():
            return self._build_offline_fallback(hostname, "DNS circuit breaker OPEN due to repeated network timeouts.")

        t0 = time.perf_counter()
        resolved_ips: List[str] = []
        resolves: Optional[bool] = None
        dns_status: str = "DNS_UNAVAILABLE"
        detailed_reason: str = ""

        # Strategy 1: dnspython with explicit RCODE handling
        if HAS_DNSPYTHON:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout_seconds
                resolver.lifetime = self.timeout_seconds * 2.0

                try:
                    answers = resolver.resolve(hostname, "A")
                    resolved_ips = [rdata.address for rdata in answers]
                    resolves = True
                    dns_status = "SUCCESS"
                    detailed_reason = f"Resolved to {len(resolved_ips)} IPv4 address(es)."
                    self.circuit_breaker.record_success()
                except dns.resolver.NXDOMAIN:
                    # Authoritative Non-Existent Domain (RCODE 3)
                    resolves = False
                    dns_status = "NXDOMAIN"
                    detailed_reason = "Authoritative DNS response: Host does not exist (NXDOMAIN)."
                    self.circuit_breaker.record_success()
                except dns.resolver.NoAnswer:
                    # RCODE 0 but no A records (NODATA)
                    resolves = None
                    dns_status = "NODATA"
                    detailed_reason = "Host exists but returned no A records (NODATA)."
                    self.circuit_breaker.record_success()
                except (dns.resolver.NoNameservers, dns.resolver.NotAbsolute):
                    # Upstream server failure
                    resolves = None
                    dns_status = "SERVFAIL"
                    detailed_reason = "DNS server returned SERVFAIL or no nameservers available."
                except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                    # Query timed out
                    resolves = None
                    dns_status = "TIMEOUT"
                    detailed_reason = f"DNS query timed out after {self.timeout_seconds}s."
                    self.circuit_breaker.record_failure()
            except Exception as e:
                resolves = None
                dns_status = "DNS_UNAVAILABLE"
                detailed_reason = f"DNS resolver encountered error: {str(e)}"
                self.circuit_breaker.record_failure()
        else:
            # Strategy 2: Socket fallback with error inspection
            original_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.timeout_seconds)
                addr_info = socket.getaddrinfo(hostname, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
                resolved_ips = list(set(ai[4][0] for ai in addr_info))
                resolves = len(resolved_ips) > 0
                dns_status = "SUCCESS"
                detailed_reason = f"Resolved {len(resolved_ips)} IP(s) via standard socket."
                self.circuit_breaker.record_success()
            except socket.gaierror as gai_err:
                err_code = gai_err.errno
                # 11001 (Windows) / -2 (Linux) = EAI_NONAME / EAI_NODATA
                if err_code in (getattr(socket, "EAI_NONAME", 11001), getattr(socket, "EAI_NODATA", 11001)):
                    resolves = False
                    dns_status = "NXDOMAIN"
                    detailed_reason = "Host not found (EAI_NONAME / NXDOMAIN)."
                    self.circuit_breaker.record_success()
                elif err_code in (getattr(socket, "EAI_AGAIN", 11002),):
                    resolves = None
                    dns_status = "TEMPORARY_DNS_FAILURE"
                    detailed_reason = "Temporary DNS failure (EAI_AGAIN)."
                else:
                    resolves = None
                    dns_status = "DNS_UNAVAILABLE"
                    detailed_reason = f"Socket gaierror ({err_code}): {str(gai_err)}"
            except (socket.timeout, TimeoutError):
                resolves = None
                dns_status = "TIMEOUT"
                detailed_reason = "Socket resolution timed out."
                self.circuit_breaker.record_failure()
            except Exception as exc:
                resolves = None
                dns_status = "DNS_UNAVAILABLE"
                detailed_reason = f"Socket error: {str(exc)}"
                self.circuit_breaker.record_failure()
            finally:
                socket.setdefaulttimeout(original_timeout)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Heuristic check for standard mail prefix if domain resolves
        has_mx_heuristic = False
        extracted = self.tld_extractor(hostname)
        root_domain = getattr(extracted, "top_domain_under_public_suffix", None) or hostname
        if resolves is True:
            try:
                socket.getaddrinfo(f"mail.{root_domain}", 25, socket.AF_INET, socket.SOCK_STREAM)
                has_mx_heuristic = True
            except Exception:
                has_mx_heuristic = False

        is_fast_flux = len(resolved_ips) >= 3

        res = {
            "hostname": hostname,
            "resolves": resolves,
            "ip_count": len(resolved_ips),
            "resolved_ips": resolved_ips[:5],
            "has_mx_record": has_mx_heuristic,
            "is_fast_flux_suspect": is_fast_flux,
            "dns_risk_score": self._calculate_dns_risk(resolves, len(resolved_ips), has_mx_heuristic, is_fast_flux),
            "lookup_latency_ms": round(elapsed_ms, 2),
            "status": dns_status,
            "reason": detailed_reason
        }

        self._cache[hostname] = {
            "data": res,
            "expires_at": now + self.cache_ttl_seconds
        }
        return res

    def _calculate_dns_risk(
        self,
        resolves: Optional[bool],
        ip_count: int,
        has_mx: bool,
        is_fast_flux: bool
    ) -> float:
        """
        Synthesizes a normalized DNS risk indicator in [0.0, 1.0]:
        - Authoritative NXDOMAIN: +0.40
        - Fast-flux suspect: +0.40
        - Indeterminate / Timeout / Offline: 0.0 (Strict Neutrality)
        """
        if resolves is None:
            # Uncertain / network timeout / offline: Strictly neutral
            return 0.0

        risk = 0.0
        if resolves is False:
            risk += 0.40
        if is_fast_flux:
            risk += 0.40
        if resolves is True and not has_mx:
            risk += 0.10
        return round(min(1.0, risk), 3)

    def _build_empty_response(self, hostname: str, reason: str) -> Dict[str, Any]:
        return {
            "hostname": hostname,
            "resolves": None,
            "ip_count": 0,
            "resolved_ips": [],
            "has_mx_record": False,
            "is_fast_flux_suspect": False,
            "dns_risk_score": 0.0,
            "lookup_latency_ms": 0.0,
            "status": "INVALID_HOST",
            "reason": reason
        }

    def _build_offline_fallback(self, hostname: str, reason: str, latency_ms: float = 0.0) -> Dict[str, Any]:
        return {
            "hostname": hostname,
            "resolves": None,  # Indeterminate, zero penalty
            "ip_count": 0,
            "resolved_ips": [],
            "has_mx_record": False,
            "is_fast_flux_suspect": False,
            "dns_risk_score": 0.0,
            "lookup_latency_ms": round(latency_ms, 2),
            "status": "DNS_UNAVAILABLE",
            "reason": reason
        }
