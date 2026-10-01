"""
Phishing Detection & Risk Intelligence Platform
URL Parser Component: Robust RFC 3986 URL parsing and decomposition.
Extracts scheme, hostname, registered domain, subdomain, path, query, fragment, port, and security flags.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress
import re
import tldextract


@dataclass
class ParsedURL:
    raw_url: str
    normalized_url: str
    scheme: str
    netloc: str
    hostname: str
    domain: str
    subdomain: str
    suffix: str
    port: Optional[int]
    path: str
    path_tokens: List[str]
    query: str
    query_params: Dict[str, List[str]]
    fragment: str
    user_info: Optional[str]
    is_ip: bool
    has_port: bool
    has_auth: bool
    is_punycode: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class URLParser:
    """
    Robust RFC-compliant URL parser designed for security analysis.
    Avoids brittle string splitting by combining Python's urlparse with tldextract and ipaddress.
    """
    def __init__(self):
        self._tld_extractor = tldextract.TLDExtract()

    def parse(self, raw_url: str) -> ParsedURL:
        if not raw_url or not isinstance(raw_url, str):
            raise ValueError("URL must be a non-empty string.")

        cleaned = raw_url.strip()
        if len(cleaned) < 3:
            raise ValueError(f"URL string too short: '{cleaned}'")
        if len(cleaned) > 2048:
            raise ValueError("URL exceeds maximum permissible length of 2048 characters.")

        # Check for user info before '@' delimiter (RFC 3986 authority credential injection)
        user_info = None
        has_auth = False
        auth_match = re.match(r"^(?:https?://)?([^/@]+)@", cleaned, re.IGNORECASE)
        if auth_match:
            user_info = auth_match.group(1)
            has_auth = True

        # Ensure scheme is present for parsing
        has_scheme = cleaned.startswith("http://") or cleaned.startswith("https://") or "://" in cleaned
        if not has_scheme:
            cleaned = "https://" + cleaned

        try:
            parsed = urlparse(cleaned)
        except Exception as e:
            raise ValueError(f"Failed to parse URL '{raw_url}': {e}")

        scheme = (parsed.scheme or "https").lower()
        netloc = parsed.netloc or ""

        # Extract port if explicitly present
        port = None
        try:
            port = parsed.port
        except ValueError:
            pass

        has_port = port is not None and port not in (80, 443)

        # Extract hostname without port and credentials
        hostname = parsed.hostname or ""
        hostname = hostname.lower()

        # Check if hostname is raw IP address (IPv4 or IPv6) or contains IP
        is_ip = False
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                if re.search(r"(?:^|\.)(?:\d{1,3}\.){3}\d{1,3}(?::|$)", hostname):
                    is_ip = True
                else:
                    is_ip = False

        # Extract registered domain, subdomain, and suffix
        ip_match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}$", hostname)
        if ip_match:
            is_ip = True
            domain = ip_match.group(0)
            subdomain = hostname[:ip_match.start()].rstrip(".")
            suffix = ""
        elif not hostname:
            domain = ""
            subdomain = ""
            suffix = ""
        else:
            ext = self._tld_extractor(hostname)
            domain = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or hostname
            domain = domain.lower()
            subdomain = ext.subdomain.lower() if ext.subdomain else ""
            suffix = ext.suffix.lower() if ext.suffix else ""

        # Path parsing and tokenization
        path = parsed.path or "/"
        clean_path = unquote(path)
        path_tokens = [tok for tok in clean_path.split("/") if tok]

        # Query parsing
        query = parsed.query or ""
        query_params = parse_qs(query) if query else {}

        # Fragment
        fragment = parsed.fragment or ""

        # Punycode check
        is_punycode = "xn--" in hostname

        # Reconstructed normalized URL
        normalized = f"{scheme}://{netloc}{path}"
        if query:
            normalized += f"?{query}"
        if fragment:
            normalized += f"#{fragment}"

        return ParsedURL(
            raw_url=raw_url,
            normalized_url=normalized,
            scheme=scheme,
            netloc=netloc.lower(),
            hostname=hostname,
            domain=domain,
            subdomain=subdomain,
            suffix=suffix,
            port=port,
            path=path,
            path_tokens=path_tokens,
            query=query,
            query_params=query_params,
            fragment=fragment,
            user_info=user_info,
            is_ip=is_ip,
            has_port=has_port,
            has_auth=has_auth,
            is_punycode=is_punycode
        )
